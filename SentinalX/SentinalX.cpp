#pragma comment(linker, "/SUBSYSTEM:WINDOWS /ENTRY:mainCRTStartup")
#include <SFML/Graphics.hpp>
#include <windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <atomic>
#include <deque>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <map>
#include <unordered_map>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wintrust.lib")

const float PI    = 3.14159265f;
const int   WIN_W = 860;
const int   WIN_H = 560;

// APP STATE

enum AppState     { IDLE, TRANSITIONING, SCANNING, ALERT, ALERT_INFO };
enum ParticleMode { FLOAT_MODE, BURST_MODE, RETRACT_MODE };


// PARTICLE TYPE SHI


struct Particle {
    sf::Vector2f pos, vel;
    float alpha, radius, life, maxLife, angle, speed;
};

sf::Vector2f g_btnCenter(430.f, 210.f);

Particle spawnParticle(ParticleMode mode) {
    Particle p;
    if (mode == BURST_MODE) {
        p.pos   = g_btnCenter;
        p.angle = (float)(rand() % 360) * PI / 180.f;
        p.speed = 2.f + (rand() % 400) / 100.f;
        p.vel   = { cosf(p.angle)*p.speed, sinf(p.angle)*p.speed };
    } else {
        p.pos   = { (float)(rand() % WIN_W), (float)(WIN_H + 10) };
        p.vel   = { ((rand()%100)-50)/120.f, -(0.25f+(rand()%50)/100.f) };
        p.angle = 0.f; p.speed = 0.f;
    }
    p.alpha   = (float)(60 + rand() % 100);
    p.radius  = 1.5f + (rand() % 3);
    p.maxLife = (mode == BURST_MODE) ? 1.5f+(rand()%2) : 5.f+(rand()%4);
    p.life    = p.maxLife;
    return p;
}

// LOGGING

std::mutex              logMutex;
std::deque<std::string> logLines; // UI mini log

std::string getTimeStr() {
    SYSTEMTIME st; GetLocalTime(&st);
    char buf[16];
    sprintf_s(buf,"%02d:%02d:%02d",st.wHour,st.wMinute,st.wSecond);
    return std::string(buf);
}

void writeFullLog(const std::string& line) {
    // always appends to file — this is what Details shows
    FILE* f;
    if (fopen_s(&f,"sentinelx_log.txt","a")==0) {
        fprintf(f,"[%s] %s\n", getTimeStr().c_str(), line.c_str());
        fclose(f);
    }
}

void addLog(const std::string& line) {
    // UI mini log (5 lines under button)
    std::lock_guard<std::mutex> lk(logMutex);
    logLines.push_front(line);
    if (logLines.size()>5) logLines.pop_back();
    // also write to full log
    writeFullLog(line);
}

void initLogFile() {
    // clear log file on startup so each session is fresh
    FILE* f;
    if (fopen_s(&f,"sentinelx_log.txt","w")==0) {
        fprintf(f,"============================================================\n");
        fprintf(f,"  SentinelX - Full Scan Log\n");
        fprintf(f,"  Session started: %s\n", getTimeStr().c_str());
        fprintf(f,"============================================================\n\n");
        fclose(f);
    }
}

// BACKEND STRUCTS


struct ProcessInfo {
    DWORD        pid;
    std::wstring name;
    double       cpuPercent;
    SIZE_T       memoryMB;
};

struct CPUSnapshot { ULONGLONG kernelTime, userTime, systemTime; };

struct ProcessHistory {
    std::deque<double> cpuReadings;
    bool      flagged   = false;
    ULONGLONG firstSeen = 0;
    void addReading(double cpu) {
        cpuReadings.push_back(cpu);
        if (cpuReadings.size()>10) cpuReadings.pop_front();
    }
    double averageCPU() {
        if (cpuReadings.empty()) return 0.0;
        double s=0; for (double r:cpuReadings) s+=r;
        return s/cpuReadings.size();
    }
};

struct ThreatScore {
    int score=0;
    std::vector<std::string> reasons;
    void add(const std::string& r){score++;reasons.push_back(r);}
    bool hasResourceSignal() const {
        for (const auto& r:reasons)
            if (r.find("CPU")    !=std::string::npos||
                r.find("memory") !=std::string::npos||
                r.find("network")!=std::string::npos||
                r.find("disk")   !=std::string::npos) return true;
        return false;
    }
};

// GLOBALS


std::atomic<bool> scanning(false);
std::atomic<int>  totalProcesses(0);
std::atomic<int>  watchingCount(0);
std::atomic<int>  flaggedCount(0);

std::atomic<bool> newThreat(false);
std::string       threatName, threatDetails;
std::mutex        threatMutex;

std::map<DWORD,CPUSnapshot>     previousSnapshots;
std::map<DWORD,ProcessHistory>  processHistories;
std::map<DWORD,IO_COUNTERS>     previousIO;
std::unordered_map<DWORD,bool>  signatureResults;
std::unordered_map<DWORD,bool>  signatureChecked;
std::mutex                      signatureMutex;
ULONGLONG                       currentTick=0;

// TRIGGER THREAT


void triggerThreat(const std::string& name, const std::string& details) {
    std::lock_guard<std::mutex> lk(threatMutex);
    threatName=name; threatDetails=details; newThreat=true;
}

// BACKEND HELPERS


std::string narrow(const std::wstring& w){return std::string(w.begin(),w.end());}

ULONGLONG filetimeToULL(FILETIME ft){
    ULARGE_INTEGER u; u.LowPart=ft.dwLowDateTime; u.HighPart=ft.dwHighDateTime;
    return u.QuadPart;
}

std::wstring getProcessPath(HANDLE h){
    wchar_t path[MAX_PATH]={}; DWORD sz=MAX_PATH;
    QueryFullProcessImageNameW(h,0,path,&sz);
    return std::wstring(path);
}

double calculateCPU(DWORD pid,ULONGLONG k,ULONGLONG u,ULONGLONG s){
    if (!previousSnapshots.count(pid)){previousSnapshots[pid]={k,u,s};return 0.0;}
    auto& prev=previousSnapshots[pid];
    ULONGLONG kd=k-prev.kernelTime,ud=u-prev.userTime,sd=s-prev.systemTime;
    double cpu=sd>0?(double)(kd+ud)/sd*100.0:0.0;
    prev={k,u,s}; return cpu;
}

int countNetworkConnections(DWORD pid){
    DWORD sz=0;
    GetExtendedTcpTable(NULL,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0);
    if (!sz) return 0;
    std::vector<BYTE> buf(sz);
    auto* t=(MIB_TCPTABLE_OWNER_PID*)buf.data();
    if (GetExtendedTcpTable(t,&sz,FALSE,AF_INET,TCP_TABLE_OWNER_PID_ALL,0)!=NO_ERROR) return 0;
    int c=0;
    for (DWORD i=0;i<t->dwNumEntries;i++)
        if (t->table[i].dwOwningPid==pid&&t->table[i].dwState==MIB_TCP_STATE_ESTAB) c++;
    return c;
}

bool isHighDiskIO(DWORD pid,HANDLE h){
    IO_COUNTERS cur; if (!GetProcessIoCounters(h,&cur)) return false;
    if (!previousIO.count(pid)){previousIO[pid]=cur;return false;}
    auto& prev=previousIO[pid];
    ULONGLONG rd=cur.ReadTransferCount-prev.ReadTransferCount;
    ULONGLONG wd=cur.WriteTransferCount-prev.WriteTransferCount;
    prev=cur; return (rd+wd)>(10ULL*1024*1024);
}

struct WCD{DWORD pid;bool hasWindow;};
BOOL CALLBACK ewCB(HWND hwnd,LPARAM lp){
    WCD* d=(WCD*)lp; DWORD wp=0;
    GetWindowThreadProcessId(hwnd,&wp);
    if (wp==d->pid&&IsWindowVisible(hwnd)){d->hasWindow=true;return FALSE;}
    return TRUE;
}
bool isHeadless(DWORD pid){WCD d={pid,false};EnumWindows(ewCB,(LPARAM)&d);return !d.hasWindow;}

bool verifySignature(const std::wstring& path){
    if (path.empty()) return false;
    WINTRUST_FILE_INFO fi={}; fi.cbStruct=sizeof(fi); fi.pcwszFilePath=path.c_str();
    GUID g=WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA td={}; td.cbStruct=sizeof(td); td.dwUIChoice=WTD_UI_NONE;
    td.fdwRevocationChecks=WTD_REVOKE_NONE; td.dwUnionChoice=WTD_CHOICE_FILE;
    td.pFile=&fi; td.dwStateAction=WTD_STATEACTION_VERIFY;
    LONG r=WinVerifyTrust(NULL,&g,&td);
    td.dwStateAction=WTD_STATEACTION_CLOSE; WinVerifyTrust(NULL,&g,&td);
    return r==ERROR_SUCCESS;
}

void signatureWorker(std::vector<ProcessInfo> procs){
    for (const auto& p:procs){
        if (p.pid<=4) continue;
        {std::lock_guard<std::mutex> lk(signatureMutex);
         if (signatureChecked.count(p.pid)) continue;
         signatureChecked[p.pid]=true;}
        HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p.pid);
        if (!h) continue;
        std::wstring path=getProcessPath(h); CloseHandle(h);
        bool s=verifySignature(path);
        {std::lock_guard<std::mutex> lk(signatureMutex); signatureResults[p.pid]=s;}
        // log every signature result to full log
        writeFullLog("[SIG] " + narrow(p.name) + " (PID "+std::to_string(p.pid)+") -> " +
            (s ? "SIGNED (trusted)" : "UNSIGNED (will be scored)"));
    }
}

bool monitorToolOpen(const std::vector<ProcessInfo>& procs){
    for (const auto& p:procs)
        if (p.name==L"Taskmgr.exe"||p.name==L"ProcessHacker.exe"||p.name==L"procexp64.exe")
            return true;
    return false;
}

std::vector<ProcessInfo> getProcesses(){
    std::vector<ProcessInfo> result;
    HANDLE snap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if (snap==INVALID_HANDLE_VALUE) return result;
    FILETIME si,sk,su; GetSystemTimes(&si,&sk,&su);
    ULONGLONG sysTime=filetimeToULL(sk)+filetimeToULL(su);
    PROCESSENTRY32 entry; entry.dwSize=sizeof(entry);
    if (Process32First(snap,&entry)){
        do {
            ProcessInfo info; info.pid=entry.th32ProcessID;
            info.name=entry.szExeFile; info.cpuPercent=0; info.memoryMB=0;
            if (!processHistories.count(info.pid)){
                processHistories[info.pid].firstSeen=currentTick;
                processHistories[info.pid].flagged=false;
            }
            HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,entry.th32ProcessID);
            if (h){
                FILETIME cr,ex,k,u;
                if (GetProcessTimes(h,&cr,&ex,&k,&u))
                    info.cpuPercent=calculateCPU(entry.th32ProcessID,
                        filetimeToULL(k),filetimeToULL(u),sysTime);
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(h,&pmc,sizeof(pmc)))
                    info.memoryMB=pmc.WorkingSetSize/(1024*1024);
                CloseHandle(h);
            }
            result.push_back(info);
        } while (Process32Next(snap,&entry));
    }
    CloseHandle(snap); return result;
}

void checkAnomalies(const std::vector<ProcessInfo>& processes, bool monitorOpen){
    int silent=0;
    for (const auto& p:processes){
        if (p.pid<=4) continue;
        if (p.name==L"SentinalX.exe"||p.name==L"SentinelX.exe") continue;
        auto& history=processHistories[p.pid];
        history.addReading(p.cpuPercent);
        if (history.flagged) continue;
        if (history.cpuReadings.size()<3) continue;
        double avgCPU=history.averageCPU();

        // log every process being actively evaluated
        writeFullLog("[SCAN] "+narrow(p.name)+
            " PID:"+std::to_string(p.pid)+
            " CPU:"+std::to_string((int)avgCPU)+"%"+
            " RAM:"+std::to_string(p.memoryMB)+"MB");

        {std::lock_guard<std::mutex> lk(signatureMutex);
         auto it=signatureResults.find(p.pid);
         if (it==signatureResults.end()){
             writeFullLog("  [SKIP] "+narrow(p.name)+" - signature not yet verified");
             continue;
         }
         if (it->second){
             writeFullLog("  [SAFE] "+narrow(p.name)+" - signed executable, skipping");
             continue;
         }}

        writeFullLog("  [UNSIGNED] "+narrow(p.name)+" - entering signal scoring...");

        // evasion check
        if (monitorOpen&&history.cpuReadings.size()>=2&&
            history.cpuReadings[history.cpuReadings.size()-2]>20.0&&
            p.cpuPercent<5.0){
            std::string dets="PID: "+std::to_string(p.pid)+"\nScore: EVASION\n\n"
                "CPU dropped "+std::to_string((int)history.cpuReadings[history.cpuReadings.size()-2])+
                "% -> "+std::to_string((int)p.cpuPercent)+
                "% the moment Task Manager opened.\n"
                "Classic cryptominer evasion technique.";
            writeFullLog("  [!!!] EVASION DETECTED: "+narrow(p.name)+
                " dropped CPU on monitor open!");
            triggerThreat(narrow(p.name),dets);
            history.flagged=true; continue;
        }

        ThreatScore threat;
        if (avgCPU>40.0){
            threat.add("Sustained high CPU ("+std::to_string((int)avgCPU)+"% avg)");
            writeFullLog("  [SIG1] HIGH CPU: "+std::to_string((int)avgCPU)+"%");
        }
        if (p.memoryMB>500){
            threat.add("High memory usage ("+std::to_string(p.memoryMB)+" MB)");
            writeFullLog("  [SIG2] HIGH MEMORY: "+std::to_string(p.memoryMB)+"MB");
        }

        HANDLE h=OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ,FALSE,p.pid);
        if (h){
            int conns=countNetworkConnections(p.pid);
            if (conns>5){
                threat.add("High network activity ("+std::to_string(conns)+" connections)");
                writeFullLog("  [SIG3] HIGH NETWORK: "+std::to_string(conns)+" connections");
            } else {
                writeFullLog("  [NET ] "+narrow(p.name)+" connections: "+std::to_string(conns));
            }
            if (isHighDiskIO(p.pid,h)){
                threat.add("Abnormal disk I/O (>10MB/interval)");
                writeFullLog("  [SIG4] HIGH DISK I/O detected");
            }
            if (isHeadless(p.pid)){
                threat.add("No visible window - headless");
                writeFullLog("  [SIG5] HEADLESS: no visible window");
            } else {
                writeFullLog("  [WIN ] "+narrow(p.name)+" has visible window");
            }
            CloseHandle(h);
        }

        writeFullLog("  [SCORE] "+narrow(p.name)+" final score: "+
            std::to_string(threat.score)+"/5");

        if (!threat.hasResourceSignal()||threat.score==1){
            writeFullLog("  [WATCH] "+narrow(p.name)+" added to watch list (score too low)");
            silent++; continue;
        }
        if (threat.score>=2){
            std::string dets="PID: "+std::to_string(p.pid)+"\n";
            dets+="Score: "+std::to_string(threat.score)+" / 5\n\nSignals fired:\n";
            for (auto& r:threat.reasons) dets+="  - "+r+"\n";
            writeFullLog("  [!!!] THREAT FLAGGED: "+narrow(p.name)+
                " score "+std::to_string(threat.score)+"/5");
            writeFullLog("------------------------------------------------------------");
            triggerThreat(narrow(p.name),dets);
            history.flagged=true; flaggedCount++;
        } else silent++;
    }
    watchingCount=silent;
}

// SCANNER THREAD


void scannerThread(){
    initLogFile();
    auto procs=getProcesses();
    std::thread(signatureWorker,procs).detach();
    addLog("[*] Signature scan started...");
    addLog("[*] Warming up CPU baselines...");
    writeFullLog("============================================================");
    writeFullLog("SCAN STARTED - "+std::to_string((int)procs.size())+" processes found");
    writeFullLog("============================================================");
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    while (scanning){
        auto processes=getProcesses();
        bool monOpen=monitorToolOpen(processes);
        totalProcesses=(int)processes.size();

        writeFullLog("\n--- TICK "+std::to_string(currentTick)+
            " | Processes: "+std::to_string((int)totalProcesses)+
            " | Monitor open: "+(monOpen?"YES":"NO")+" ---");

        if (currentTick%30==0) std::thread(signatureWorker,processes).detach();
        checkAnomalies(processes,monOpen);

        if (currentTick%4==0){
            char buf[80];
            sprintf_s(buf,"[%llu] Tracking %d | Watching: %d | Flagged: %d",
                currentTick,(int)totalProcesses,(int)watchingCount,(int)flaggedCount);
            addLog(std::string(buf));
        }
        if (monOpen) addLog("[~] Monitor tool open - checking evasion...");
        currentTick++;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }
    writeFullLog("\n============================================================");
    writeFullLog("SCAN STOPPED BY USER");
    writeFullLog("============================================================");
}

// UI HELPERS


sf::Color lerpColor(sf::Color a,sf::Color b,float t){
    t=std::max(0.f,std::min(1.f,t));
    return sf::Color((sf::Uint8)(a.r+(b.r-a.r)*t),(sf::Uint8)(a.g+(b.g-a.g)*t),
                     (sf::Uint8)(a.b+(b.b-a.b)*t),(sf::Uint8)(a.a+(b.a-a.a)*t));
}

void drawArc(sf::RenderWindow& w,sf::Vector2f c,float r,float s,float e,sf::Color col){
    const int segs=80; sf::VertexArray arc(sf::LineStrip,segs+1);
    for (int i=0;i<=segs;i++){
        float a=(s+(e-s)*i/segs)*PI/180.f;
        arc[i].position={c.x+r*cosf(a),c.y+r*sinf(a)};
        arc[i].color=col;
    }
    w.draw(arc);
}

bool mouseOverCircle(sf::Vector2f center,float r,const sf::RenderWindow& win){
    sf::Vector2f m((float)sf::Mouse::getPosition(win).x,(float)sf::Mouse::getPosition(win).y);
    float dx=m.x-center.x,dy=m.y-center.y; return dx*dx+dy*dy<=r*r;
}

bool mouseOverRect(const sf::RectangleShape& rect,const sf::RenderWindow& win){
    sf::Vector2f m((float)sf::Mouse::getPosition(win).x,(float)sf::Mouse::getPosition(win).y);
    return rect.getGlobalBounds().contains(m);
}

void centerText(sf::Text& t,sf::Vector2f pos){
    sf::FloatRect b=t.getLocalBounds();
    t.setOrigin(b.left+b.width/2.f,b.top+b.height/2.f);
    t.setPosition(pos);
}

void setCC(sf::CircleShape& c,sf::Vector2f pos){
    c.setOrigin(c.getRadius(),c.getRadius()); c.setPosition(pos);
}

// MAIN


int main(){
    srand((unsigned)time(nullptr));

    sf::ContextSettings settings; settings.antialiasingLevel=8;
    sf::RenderWindow window(sf::VideoMode(WIN_W,WIN_H),
        "SentinelX - Malware Detection Engine",
        sf::Style::Titlebar|sf::Style::Close,settings);
    window.setFramerateLimit(60);

    sf::VideoMode desktop=sf::VideoMode::getDesktopMode();
    window.setPosition(sf::Vector2i(
        (int)(desktop.width-WIN_W)/2,
        (int)(desktop.height-WIN_H)/2));

    sf::Font font;
    if (!font.loadFromFile("C:\\Windows\\Fonts\\consola.ttf"))
        font.loadFromFile("C:\\Windows\\Fonts\\arial.ttf");

    sf::Cursor arrowCursor,handCursor;
    arrowCursor.loadFromSystem(sf::Cursor::Arrow);
    handCursor.loadFromSystem(sf::Cursor::Hand);

    AppState     state        = IDLE;
    ParticleMode particleMode = FLOAT_MODE;
    float transitionT=0.f, arcAngle=-90.f, glowPulse=0.f;
    float alertFlipT=0.f, burstTimer=0.f;
    int   alertFlipN=0;
    bool  alertFlipRed=true, alertDone=false;
    std::string alertName,alertDets;

    const float BTN_R=95.f;
    sf::Color colIdle(180,30,30),colActive(0,150,70);

    sf::CircleShape glow1(BTN_R+32); glow1.setPointCount(100);
    sf::CircleShape glow2(BTN_R+18); glow2.setPointCount(100);
    sf::CircleShape mainBtn(BTN_R);  mainBtn.setPointCount(100);
    sf::CircleShape highlight(BTN_R*0.42f); highlight.setPointCount(100);

    setCC(glow1,g_btnCenter); setCC(glow2,g_btnCenter); setCC(mainBtn,g_btnCenter);
    highlight.setOrigin(highlight.getRadius(),highlight.getRadius());
    highlight.setPosition(g_btnCenter.x-BTN_R*0.28f,g_btnCenter.y-BTN_R*0.28f);

    glow1.setFillColor(sf::Color(180,30,30,18));
    glow2.setFillColor(sf::Color(180,30,30,38));
    mainBtn.setFillColor(colIdle);
    mainBtn.setOutlineThickness(3);
    mainBtn.setOutlineColor(sf::Color(220,60,60));
    highlight.setFillColor(sf::Color(255,255,255,30));

    sf::Text btnLabel;
    btnLabel.setFont(font); btnLabel.setString("INITIALIZE");
    btnLabel.setCharacterSize(20); btnLabel.setStyle(sf::Text::Bold);
    btnLabel.setFillColor(sf::Color::White);
    centerText(btnLabel,g_btnCenter);

    sf::Text statusText;
    statusText.setFont(font); statusText.setString("Click to begin scanning");
    statusText.setCharacterSize(13); statusText.setFillColor(sf::Color(120,120,120));
    centerText(statusText,{WIN_W/2.f,g_btnCenter.y+BTN_R+24.f});

    sf::Text statsText;
    statsText.setFont(font); statsText.setString("PROCS: --   WATCHING: --   FLAGGED: --");
    statsText.setCharacterSize(12); statsText.setFillColor(sf::Color(0,200,100));
    statsText.setPosition(32,340);

    sf::RectangleShape divider(sf::Vector2f(WIN_W-60.f,1));
    divider.setPosition(30,362); divider.setFillColor(sf::Color(32,32,32));

    sf::RectangleShape consoleBg(sf::Vector2f(WIN_W-60.f,145));
    consoleBg.setPosition(30,368); consoleBg.setFillColor(sf::Color(10,10,10));
    consoleBg.setOutlineThickness(1); consoleBg.setOutlineColor(sf::Color(26,26,26));

    std::vector<sf::Text> logTexts(5);
    for (int i=0;i<5;i++){
        logTexts[i].setFont(font); logTexts[i].setCharacterSize(11);
        logTexts[i].setFillColor(sf::Color(0,175,75));
        logTexts[i].setPosition(40,376+i*21);
    }

    auto makeTopBtn=[](float x){
        sf::RectangleShape b(sf::Vector2f(95,30));
        b.setPosition(x,12); b.setFillColor(sf::Color(20,20,20));
        b.setOutlineThickness(1); b.setOutlineColor(sf::Color(45,45,45));
        return b;
    };
    sf::RectangleShape detailsBtn=makeTopBtn(12.f);
    sf::RectangleShape creditsBtn=makeTopBtn(WIN_W-107.f);

    sf::Text detailsLabel,creditsLabel;
    detailsLabel.setFont(font); detailsLabel.setString("DETAILS");
    creditsLabel.setFont(font); creditsLabel.setString("CREDITS");
    for (auto* t:{&detailsLabel,&creditsLabel}){
        t->setCharacterSize(12); t->setFillColor(sf::Color(150,150,150));
    }
    detailsLabel.setPosition(22,19);
    creditsLabel.setPosition(WIN_W-97.f,19);

    sf::Text titleText;
    titleText.setFont(font); titleText.setString("SentinelX");
    titleText.setCharacterSize(16); titleText.setStyle(sf::Text::Bold);
    titleText.setFillColor(sf::Color(0,200,100));
    centerText(titleText,{WIN_W/2.f,26.f});

    sf::RectangleShape bg(sf::Vector2f(WIN_W,WIN_H));
    bg.setFillColor(sf::Color(8,8,8));

    std::vector<Particle> particles;
    for (int i=0;i<55;i++){
        auto p=spawnParticle(FLOAT_MODE);
        p.pos.y=(float)(rand()%WIN_H);
        particles.push_back(p);
    }
    sf::CircleShape partShape; partShape.setPointCount(8);

    sf::RectangleShape alertOverlay(sf::Vector2f(WIN_W,WIN_H));

    sf::Text checkmateText;
    checkmateText.setFont(font); checkmateText.setString("CHECKMATE");
    checkmateText.setCharacterSize(72); checkmateText.setStyle(sf::Text::Bold);
    centerText(checkmateText,{WIN_W/2.f,WIN_H/2.f-50.f});

    sf::Text alertSubText;
    alertSubText.setFont(font);
    alertSubText.setString("THREAT DETECTED  |  Click anywhere to view details");
    alertSubText.setCharacterSize(14);
    centerText(alertSubText,{WIN_W/2.f,WIN_H/2.f+40.f});

    sf::Text infoTitle,infoBody,infoDismiss;
    infoTitle.setFont(font); infoTitle.setCharacterSize(18);
    infoTitle.setStyle(sf::Text::Bold); infoTitle.setFillColor(sf::Color(220,50,50));
    infoBody.setFont(font); infoBody.setCharacterSize(13);
    infoBody.setFillColor(sf::Color(200,200,200)); infoBody.setPosition(80,WIN_H/2.f-60.f);
    infoDismiss.setFont(font); infoDismiss.setString("Click or press any key to dismiss");
    infoDismiss.setCharacterSize(12); infoDismiss.setFillColor(sf::Color(70,70,70));
    centerText(infoDismiss,{WIN_W/2.f,WIN_H-28.f});

    std::thread* scanThread=nullptr;
    sf::Clock    dtClock;

    while (window.isOpen()){
        float dt=dtClock.restart().asSeconds();
        if (dt>0.05f) dt=0.05f;

        sf::Event event;
        while (window.pollEvent(event)){
            if (event.type==sf::Event::Closed){scanning=false;window.close();}

            if (event.type==sf::Event::KeyPressed){
                if (event.key.code==sf::Keyboard::T&&state==SCANNING)
                    triggerThreat("malware_test.exe",
                        "PID: 9999\nScore: 4 / 5\n\nSignals fired:\n"
                        "  - Sustained high CPU (87% avg)\n"
                        "  - No visible window - headless\n"
                        "  - Abnormal disk I/O (>10MB/interval)\n"
                        "  - High network activity (12 connections)\n");
                if (state==ALERT_INFO) state=SCANNING;
            }

            if (event.type==sf::Event::MouseButtonPressed){
                if (state==ALERT&&alertDone){
                    {std::lock_guard<std::mutex> lk(threatMutex);
                     alertName=threatName; alertDets=threatDetails;}
                    infoTitle.setString("!! THREAT FOUND: "+alertName);
                    centerText(infoTitle,{WIN_W/2.f,80.f});
                    infoBody.setString(alertDets);
                    state=ALERT_INFO;
                }
                if (state==ALERT_INFO) state=SCANNING;

                if (state==IDLE&&mouseOverCircle(g_btnCenter,BTN_R,window)){
                    state=TRANSITIONING; transitionT=0.f;
                }
                if (state==SCANNING&&mouseOverCircle(g_btnCenter,BTN_R,window)){
                    scanning=false;
                    if (scanThread&&scanThread->joinable()) scanThread->join();
                    delete scanThread; scanThread=nullptr;
                    particleMode=RETRACT_MODE; burstTimer=0.f;
                    state=IDLE;
                    mainBtn.setFillColor(colIdle);
                    mainBtn.setOutlineColor(sf::Color(220,60,60));
                    glow1.setFillColor(sf::Color(180,30,30,18));
                    glow2.setFillColor(sf::Color(180,30,30,38));
                    btnLabel.setString("INITIALIZE");
                    centerText(btnLabel,g_btnCenter);
                    statusText.setString("Click to begin scanning");
                    statusText.setFillColor(sf::Color(120,120,120));
                    centerText(statusText,{WIN_W/2.f,g_btnCenter.y+BTN_R+24.f});
                    addLog("[*] Scan stopped by user.");
                }

                // DETAILS — opens live log in powershell
                if (mouseOverRect(detailsBtn,window))
                    ShellExecuteA(NULL,"open","powershell.exe",
                        "-NoExit -Command \"Get-Content -Wait sentinelx_log.txt\"",
                        NULL,SW_SHOW);

                // CREDITS
                if (mouseOverRect(creditsBtn,window))
                    ShellExecuteA(NULL,"open",
                        "https://github.com/Khawaja-saad-waheed/SentinalX",
                        NULL,NULL,SW_SHOWNORMAL);
            }
        }

        bool overBtn=mouseOverCircle(g_btnCenter,BTN_R,window);
        bool overDet=mouseOverRect(detailsBtn,window);
        bool overCre=mouseOverRect(creditsBtn,window);
        window.setMouseCursor((overBtn||overDet||overCre)?handCursor:arrowCursor);
        detailsBtn.setFillColor(overDet?sf::Color(35,35,35):sf::Color(20,20,20));
        creditsBtn.setFillColor(overCre?sf::Color(35,35,35):sf::Color(20,20,20));

        if (state==IDLE){
            mainBtn.setOutlineThickness(overBtn?5.f:3.f);
            mainBtn.setOutlineColor(overBtn?sf::Color(255,90,90):sf::Color(220,60,60));
        }

        if (state==TRANSITIONING){
            transitionT+=dt*1.1f;
            if (transitionT>=1.f){
                transitionT=1.f; state=SCANNING; scanning=true;
                scanThread=new std::thread(scannerThread);
                particleMode=BURST_MODE; burstTimer=0.f;
                for (auto& p:particles) p=spawnParticle(BURST_MODE);
                btnLabel.setString("WATCHING");
                centerText(btnLabel,g_btnCenter);
                statusText.setString("Active  -  monitoring all processes");
                statusText.setFillColor(sf::Color(0,200,80));
                centerText(statusText,{WIN_W/2.f,g_btnCenter.y+BTN_R+24.f});
            }
            sf::Color c=lerpColor(colIdle,colActive,transitionT);
            mainBtn.setFillColor(c);
            mainBtn.setOutlineColor(lerpColor(sf::Color(220,60,60),sf::Color(0,220,100),transitionT));
            glow1.setFillColor(sf::Color(c.r,c.g,c.b,18));
            glow2.setFillColor(sf::Color(c.r,c.g,c.b,38));
        }

        glowPulse+=dt*2.2f;
        {sf::Color gc=glow1.getFillColor();
         gc.a=(sf::Uint8)(18.f+14.f*sinf(glowPulse));
         glow1.setFillColor(gc);}

        if (state==SCANNING||state==TRANSITIONING) arcAngle+=160.f*dt;

        if (state==SCANNING){
            char buf[80];
            sprintf_s(buf,"PROCS: %d   WATCHING: %d   FLAGGED: %d",
                (int)totalProcesses,(int)watchingCount,(int)flaggedCount);
            statsText.setString(buf);
        }

        {std::lock_guard<std::mutex> lk(logMutex);
         for (int i=0;i<5&&i<(int)logLines.size();i++)
             logTexts[i].setString(logLines[i]);}

        for (auto& p:particles){
            if (particleMode==BURST_MODE){
                p.pos+=p.vel; p.vel*=0.97f; p.life-=dt;
                if (p.life<=0) p=spawnParticle(BURST_MODE);
            } else if (particleMode==RETRACT_MODE){
                sf::Vector2f dir=g_btnCenter-p.pos;
                float dist=sqrtf(dir.x*dir.x+dir.y*dir.y);
                if (dist>2.f) p.pos+=(dir/dist)*4.f;
                p.life-=dt*0.5f;
            } else {
                p.pos+=p.vel; p.life-=dt;
                if (p.life<=0||p.pos.y<-10) p=spawnParticle(FLOAT_MODE);
            }
        }

        if (particleMode==BURST_MODE){
            burstTimer+=dt;
            if (burstTimer>1.5f){
                particleMode=FLOAT_MODE;
                for (auto& p:particles) p=spawnParticle(FLOAT_MODE);
            }
        }
        if (particleMode==RETRACT_MODE){
            burstTimer+=dt;
            if (burstTimer>1.0f){
                particleMode=FLOAT_MODE;
                for (auto& p:particles) p=spawnParticle(FLOAT_MODE);
            }
        }

        if (newThreat&&state==SCANNING){
            newThreat=false; state=ALERT;
            alertFlipRed=true; alertFlipT=0.f;
            alertFlipN=0; alertDone=false;
            SetForegroundWindow(window.getSystemHandle());
            ShowWindow(window.getSystemHandle(),SW_RESTORE);
            SetWindowPos(window.getSystemHandle(),HWND_TOPMOST,0,0,0,0,
                SWP_NOMOVE|SWP_NOSIZE);
        }

        if (state==ALERT){
            alertFlipT+=dt;
            if (alertFlipT>=0.075f){
                alertFlipT=0.f; alertFlipRed=!alertFlipRed; alertFlipN++;
                if (alertFlipN>=18) alertDone=true;
            }
            alertOverlay.setFillColor(alertFlipRed?sf::Color(200,0,0):sf::Color(255,255,255));
            checkmateText.setFillColor(sf::Color::Black);
            alertSubText.setFillColor(sf::Color::Black);
        }

        if (state==SCANNING)
            SetWindowPos(window.getSystemHandle(),HWND_NOTOPMOST,0,0,0,0,SWP_NOMOVE|SWP_NOSIZE);

        //DRAW
        window.clear(sf::Color(8,8,8));

        if (state==ALERT){
            window.draw(alertOverlay);
            window.draw(checkmateText);
            if (alertDone) window.draw(alertSubText);

        } else if (state==ALERT_INFO){
            window.draw(infoTitle);
            window.draw(infoBody);
            window.draw(infoDismiss);

        } else {
            window.draw(bg);

            for (auto& p:particles){
                float a=(p.life/p.maxLife)*p.alpha;
                partShape.setRadius(p.radius);
                partShape.setOrigin(p.radius,p.radius);
                partShape.setPosition(p.pos);
                sf::Color pc;
                if (particleMode==BURST_MODE||particleMode==RETRACT_MODE)
                    pc=sf::Color(220,40,40,(sf::Uint8)std::min(255.f,a));
                else pc=(state==SCANNING||state==TRANSITIONING)
                    ?sf::Color(0,180,80,(sf::Uint8)std::min(255.f,a))
                    :sf::Color(180,40,40,(sf::Uint8)std::min(255.f,a*0.5f));
                partShape.setFillColor(pc);
                window.draw(partShape);
            }

            window.draw(titleText);
            window.draw(detailsBtn); window.draw(detailsLabel);
            window.draw(creditsBtn); window.draw(creditsLabel);
            window.draw(glow1); window.draw(glow2);
            window.draw(mainBtn); window.draw(highlight);
            window.draw(btnLabel);

            if (state==SCANNING||state==TRANSITIONING){
                float alpha=(state==TRANSITIONING)?transitionT*255.f:255.f;
                drawArc(window,g_btnCenter,BTN_R+14,arcAngle,arcAngle+250,
                    sf::Color(0,220,100,(sf::Uint8)alpha));
                drawArc(window,g_btnCenter,BTN_R+22,arcAngle+180,arcAngle+310,
                    sf::Color(0,160,70,(sf::Uint8)(alpha*0.35f)));
            }

            window.draw(statusText);
            window.draw(statsText);
            window.draw(divider);
            window.draw(consoleBg);
            for (auto& t:logTexts) window.draw(t);
        }

        window.display();
    }

    scanning=false;
    if (scanThread&&scanThread->joinable()) scanThread->join();
    delete scanThread;
    return 0;
}
