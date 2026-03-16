#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <mutex>
#include <unordered_map>
#include <map>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <iomanip>
#include <deque>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "wintrust.lib")

// --- Console Colors ----------------------------------------------------------

void setColor(int c) {
    SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), c);
}
void resetColor() { setColor(15); }

// --- Banner ------------------------------------------------------------------

void printBanner() {
    system("cls");
    setColor(10);
    std::wcout << L"\n";
    std::wcout << L"   ____  _____ _   _ _____ ___ _   _ _____ _     __  __\n";
    std::wcout << L"  / ___|| ____| \\ | |_   _|_ _| \\ | | ____| |   \\ \\/ /\n";
    std::wcout << L"  \\___ \\|  _| |  \\| | | |  | ||  \\| |  _| | |    >  <\n";
    std::wcout << L"   ___) | |___| |\\  | | |  | || |\\  | |___| |___/ /\\ \\\n";
    std::wcout << L"  |____/|_____|_| \\_| |_| |___|_| \\_|_____|_____/_/  \\_\\\n\n";
    setColor(8);
    std::wcout << L"  ================================================================\n";
    setColor(11);
    std::wcout << L"               MALWARE DETECTION ENGINE  v0.8\n";
    setColor(8);
    std::wcout << L"  ================================================================\n";
    setColor(2);
    std::wcout << L"  [SIG] Signature Verify    [EVA] Evasion Detection\n";
    std::wcout << L"  [NET] Network Analysis    [MEM] Memory Profiling\n";
    std::wcout << L"  [DSK] Disk I/O Monitor    [CPU] Process Scoring\n";
    setColor(8);
    std::wcout << L"  ================================================================\n\n";
    resetColor();
}

void animateStartup() {
    std::vector<std::wstring> steps = {
        L"  [....] Initializing kernel hooks      ",
        L"  [....] Loading signature database     ",
        L"  [....] Mapping process tree           ",
        L"  [....] Calibrating CPU baselines      ",
        L"  [....] Activating evasion tripwires   ",
        L"  [....] Starting network listener      ",
    };

    for (auto& step : steps) {
        setColor(8);
        std::wcout << step << L"\r";
        std::wcout.flush();
        Sleep(350);
        std::wstring done = step;
        done.replace(3, 4, L" OK ");
        setColor(10);
        std::wcout << done << L"\n";
    }

    std::wcout << L"\n";
    setColor(10);
    std::wcout << L"  >> ALL SYSTEMS ONLINE. MONITORING ACTIVE.\n\n";
    resetColor();
}

// --- Utilities ---------------------------------------------------------------

ULONGLONG filetimeToULL(FILETIME ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

std::wstring getProcessPath(HANDLE hProcess) {
    wchar_t path[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    QueryFullProcessImageNameW(hProcess, 0, path, &size);
    return std::wstring(path);
}

std::wstring getTimestamp() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf_s(buf, 32, L"%02d:%02d:%02d", st.wHour, st.wMinute, st.wSecond);
    return std::wstring(buf);
}

std::wstring toWStr(int n) { return std::to_wstring(n); }
std::wstring toWStr(SIZE_T n) { return std::to_wstring(n); }
std::wstring toWStr(double n) { return std::to_wstring((int)n); }

// --- Data Structures ---------------------------------------------------------

struct ProcessInfo {
    DWORD        pid;
    std::wstring name;
    double       cpuPercent;
    SIZE_T       memoryMB;
};

struct CPUSnapshot {
    ULONGLONG kernelTime;
    ULONGLONG userTime;
    ULONGLONG systemTime;
};

struct ProcessHistory {
    std::deque<double> cpuReadings;
    bool               flagged = false;
    ULONGLONG          firstSeen = 0;

    void addReading(double cpu) {
        cpuReadings.push_back(cpu);
        if (cpuReadings.size() > 10)
            cpuReadings.pop_front();
    }

    double averageCPU() {
        if (cpuReadings.empty()) return 0.0;
        double sum = 0;
        for (double r : cpuReadings) sum += r;
        return sum / cpuReadings.size();
    }
};

struct ThreatScore {
    int                       score = 0;
    std::vector<std::wstring> reasons;

    void add(const std::wstring& reason) {
        score++;
        reasons.push_back(reason);
    }

    bool hasResourceSignal() const {
        for (const auto& r : reasons)
            if (r.find(L"CPU") != std::wstring::npos ||
                r.find(L"memory") != std::wstring::npos ||
                r.find(L"network") != std::wstring::npos ||
                r.find(L"disk") != std::wstring::npos)
                return true;
        return false;
    }
};

// --- Global State ------------------------------------------------------------

std::map<DWORD, CPUSnapshot>     previousSnapshots;
std::map<DWORD, ProcessHistory>  processHistories;
std::map<DWORD, IO_COUNTERS>     previousIO;
std::unordered_map<DWORD, bool>  signatureResults;
std::unordered_map<DWORD, bool>  signatureChecked;
std::mutex                       signatureMutex;
ULONGLONG                        currentTick = 0;
int                              totalFlagged = 0;

// --- CPU Calculation ---------------------------------------------------------

double calculateCPU(DWORD pid, ULONGLONG curKernel,
    ULONGLONG curUser, ULONGLONG curSystem) {
    if (previousSnapshots.find(pid) == previousSnapshots.end()) {
        previousSnapshots[pid] = { curKernel, curUser, curSystem };
        return 0.0;
    }
    CPUSnapshot& prev = previousSnapshots[pid];
    ULONGLONG kDiff = curKernel - prev.kernelTime;
    ULONGLONG uDiff = curUser - prev.userTime;
    ULONGLONG sDiff = curSystem - prev.systemTime;
    double cpu = 0.0;
    if (sDiff > 0)
        cpu = (double)(kDiff + uDiff) / sDiff * 100.0;
    prev = { curKernel, curUser, curSystem };
    return cpu;
}

// --- Signal Checkers ---------------------------------------------------------

int countNetworkConnections(DWORD pid) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
    if (size == 0) return 0;
    std::vector<BYTE> buffer(size);
    auto* table = (MIB_TCPTABLE_OWNER_PID*)buffer.data();
    if (GetExtendedTcpTable(table, &size, FALSE, AF_INET,
        TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) return 0;
    int count = 0;
    for (DWORD i = 0; i < table->dwNumEntries; i++)
        if (table->table[i].dwOwningPid == pid &&
            table->table[i].dwState == MIB_TCP_STATE_ESTAB)
            count++;
    return count;
}

bool isHighDiskIO(DWORD pid, HANDLE hProcess) {
    IO_COUNTERS current;
    if (!GetProcessIoCounters(hProcess, &current)) return false;
    if (previousIO.find(pid) == previousIO.end()) {
        previousIO[pid] = current;
        return false;
    }
    IO_COUNTERS& prev = previousIO[pid];
    ULONGLONG readDelta = current.ReadTransferCount - prev.ReadTransferCount;
    ULONGLONG writeDelta = current.WriteTransferCount - prev.WriteTransferCount;
    prev = current;
    return (readDelta + writeDelta) > (10ULL * 1024 * 1024);
}

struct WindowCheckData { DWORD pid; bool hasWindow; };

BOOL CALLBACK enumWindowsCallback(HWND hwnd, LPARAM lParam) {
    auto* data = (WindowCheckData*)lParam;
    DWORD windowPID = 0;
    GetWindowThreadProcessId(hwnd, &windowPID);
    if (windowPID == data->pid && IsWindowVisible(hwnd)) {
        data->hasWindow = true;
        return FALSE;
    }
    return TRUE;
}

bool isHeadless(DWORD pid) {
    WindowCheckData data = { pid, false };
    EnumWindows(enumWindowsCallback, (LPARAM)&data);
    return !data.hasWindow;
}

// --- Signature Checker -------------------------------------------------------

bool verifySignature(const std::wstring& path) {
    if (path.empty()) return false;
    WINTRUST_FILE_INFO fileInfo = {};
    fileInfo.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileInfo.pcwszFilePath = path.c_str();
    GUID policyGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA trustData = {};
    trustData.cbStruct = sizeof(WINTRUST_DATA);
    trustData.dwUIChoice = WTD_UI_NONE;
    trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    trustData.dwUnionChoice = WTD_CHOICE_FILE;
    trustData.pFile = &fileInfo;
    trustData.dwStateAction = WTD_STATEACTION_VERIFY;
    LONG result = WinVerifyTrust(NULL, &policyGUID, &trustData);
    trustData.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(NULL, &policyGUID, &trustData);
    return result == ERROR_SUCCESS;
}

void signatureWorker(std::vector<ProcessInfo> processes) {
    for (const auto& p : processes) {
        if (p.pid <= 4) continue;
        {
            std::lock_guard<std::mutex> lock(signatureMutex);
            if (signatureChecked.count(p.pid)) continue;
            signatureChecked[p.pid] = true;
        }
        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, p.pid);
        if (!hProcess) continue;
        std::wstring path = getProcessPath(hProcess);
        CloseHandle(hProcess);
        bool isSigned = verifySignature(path);
        {
            std::lock_guard<std::mutex> lock(signatureMutex);
            signatureResults[p.pid] = isSigned;
        }
    }
}

// --- Process Scanner ---------------------------------------------------------

std::vector<ProcessInfo> getProcesses() {
    std::vector<ProcessInfo> result;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return result;
    FILETIME sysIdle, sysKernel, sysUser;
    GetSystemTimes(&sysIdle, &sysKernel, &sysUser);
    ULONGLONG systemTime = filetimeToULL(sysKernel) + filetimeToULL(sysUser);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &entry)) {
        do {
            ProcessInfo info;
            info.pid = entry.th32ProcessID;
            info.name = entry.szExeFile;
            info.cpuPercent = 0.0;
            info.memoryMB = 0;
            if (processHistories.find(info.pid) == processHistories.end()) {
                processHistories[info.pid].firstSeen = currentTick;
                processHistories[info.pid].flagged = false;
            }
            HANDLE hProcess = OpenProcess(
                PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                FALSE, entry.th32ProcessID);
            if (hProcess) {
                FILETIME creation, exitT, kernel, user;
                if (GetProcessTimes(hProcess, &creation, &exitT, &kernel, &user))
                    info.cpuPercent = calculateCPU(
                        entry.th32ProcessID,
                        filetimeToULL(kernel),
                        filetimeToULL(user),
                        systemTime);
                PROCESS_MEMORY_COUNTERS pmc;
                if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
                    info.memoryMB = pmc.WorkingSetSize / (1024 * 1024);
                CloseHandle(hProcess);
            }
            result.push_back(info);
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);
    return result;
}

bool monitorToolOpen(const std::vector<ProcessInfo>& processes) {
    for (const auto& p : processes)
        if (p.name == L"Taskmgr.exe" ||
            p.name == L"ProcessHacker.exe" ||
            p.name == L"procexp64.exe")
            return true;
    return false;
}

// --- Status Bar --------------------------------------------------------------

void printStatusBar(size_t procCount, bool monitorOpen,
    size_t sigsChecked, int silentCount) {
    setColor(8);
    std::wcout << L"  ----------------------------------------------------------------\n";
    std::wcout << L"  ";
    setColor(2);  std::wcout << getTimestamp();
    setColor(8);  std::wcout << L" | ";
    setColor(11); std::wcout << L"PROCS:";
    setColor(10); std::wcout << std::setw(4) << procCount;
    setColor(8);  std::wcout << L" | ";
    setColor(11); std::wcout << L"SIGS:";
    setColor(10); std::wcout << std::setw(4) << sigsChecked;
    setColor(8);  std::wcout << L" | ";
    setColor(11); std::wcout << L"WATCH:";
    setColor(14); std::wcout << std::setw(4) << silentCount;
    setColor(8);  std::wcout << L" | ";
    setColor(11); std::wcout << L"FLAGGED:";
    setColor(totalFlagged > 0 ? 12 : 10);
    std::wcout << std::setw(3) << totalFlagged;
    setColor(8);  std::wcout << L" | ";
    setColor(11); std::wcout << L"MONITOR:";
    if (monitorOpen) { setColor(14); std::wcout << L" OPEN"; }
    else { setColor(10); std::wcout << L" NONE"; }
    std::wcout << L"\n";
    setColor(8);
    std::wcout << L"  ----------------------------------------------------------------\n";
    resetColor();
}

// --- Anomaly Engine ----------------------------------------------------------

void checkAnomalies(const std::vector<ProcessInfo>& processes, bool monitorOpen) {
    int    silentCount = 0;
    size_t sigsReady = 0;
    {
        std::lock_guard<std::mutex> lock(signatureMutex);
        sigsReady = signatureResults.size();
    }

    for (const auto& p : processes) {
        if (p.pid <= 4) continue;
        if (p.name == L"SentinalX.exe" || p.name == L"SentinelX.exe") continue;

        ProcessHistory& history = processHistories[p.pid];
        history.addReading(p.cpuPercent);

        if (history.flagged)                continue;
        if (history.cpuReadings.size() < 3) continue;

        double avgCPU = history.averageCPU();

        {
            std::lock_guard<std::mutex> lock(signatureMutex);
            auto it = signatureResults.find(p.pid);
            if (it == signatureResults.end()) continue;
            if (it->second)                  continue;
        }

        // evasion check
        if (monitorOpen &&
            history.cpuReadings.size() >= 2 &&
            history.cpuReadings[history.cpuReadings.size() - 2] > 20.0 &&
            p.cpuPercent < 5.0) {

            MessageBeep(MB_ICONERROR);
            setColor(12);
            std::wcout << L"\n  *** EVASION DETECTED ***\n";
            std::wcout << L"  PROCESS  : " << p.name << L" (PID " << p.pid << L")\n";
            std::wcout << L"  BEHAVIOR : CPU dropped "
                << history.cpuReadings[history.cpuReadings.size() - 2]
                << L"% -> " << p.cpuPercent
                << L"% on monitor open\n";
            std::wcout << L"  TIME     : " << getTimestamp() << L"\n\n";
            resetColor();
            history.flagged = true;
            totalFlagged++;
            continue;
        }

        // five signal scoring
        ThreatScore threat;

        if (avgCPU > 40.0)
            threat.add(L"Sustained high CPU (" + toWStr(avgCPU) + L"% avg)");

        if (p.memoryMB > 500)
            threat.add(L"High memory usage (" + toWStr(p.memoryMB) + L" MB)");

        HANDLE hProcess = OpenProcess(
            PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
            FALSE, p.pid);

        if (hProcess) {
            int conns = countNetworkConnections(p.pid);
            if (conns > 5)
                threat.add(L"High network activity (" + toWStr(conns) + L" connections)");
            if (isHighDiskIO(p.pid, hProcess))
                threat.add(L"Abnormal disk I/O (>10MB/interval)");
            if (isHeadless(p.pid))
                threat.add(L"No visible window - headless");
            CloseHandle(hProcess);
        }

        if (!threat.hasResourceSignal() || threat.score == 1) {
            silentCount++;
            continue;
        }

        if (threat.score >= 2) {
            totalFlagged++;
            std::wcout << L"\n";

            if (threat.score >= 4) {
                MessageBeep(MB_ICONERROR);
                setColor(12);
                std::wcout << L"  *** CRITICAL THREAT ***\n";
            }
            else if (threat.score == 3) {
                setColor(4);
                std::wcout << L"  *** HIGH THREAT ***\n";
            }
            else {
                setColor(14);
                std::wcout << L"  *** SUSPICIOUS PROCESS ***\n";
            }

            setColor(threat.score >= 3 ? 4 : 14);
            std::wcout << L"  PROCESS  : " << p.name << L" (PID " << p.pid << L")\n";
            std::wcout << L"  SCORE    : " << threat.score << L"/5  [";
            setColor(12);
            for (int i = 0; i < threat.score; i++) std::wcout << L"#";
            setColor(8);
            for (int i = threat.score; i < 5; i++) std::wcout << L".";
            setColor(threat.score >= 3 ? 4 : 14);
            std::wcout << L"]\n";
            std::wcout << L"  TIME     : " << getTimestamp() << L"\n";
            std::wcout << L"  SIGNALS  :\n";
            for (const auto& reason : threat.reasons) {
                setColor(8);  std::wcout << L"    +-- ";
                setColor(15); std::wcout << reason << L"\n";
            }
            std::wcout << L"\n";
            resetColor();
            history.flagged = true;
        }
    }

    printStatusBar(processes.size(), monitorOpen, sigsReady, silentCount);
}

// --- Main --------------------------------------------------------------------

int main() {
    SetConsoleTitleA("SentinelX - Malware Detection Engine");

    HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
    SMALL_RECT windowSize = { 0, 0, 100, 40 };
    SetConsoleWindowInfo(hConsole, TRUE, &windowSize);
    COORD bufferSize = { 101, 3000 };
    SetConsoleScreenBufferSize(hConsole, bufferSize);

    // set console to unicode mode
    SetConsoleOutputCP(CP_UTF8);

    printBanner();
    animateStartup();

    auto procs = getProcesses();
    std::thread(signatureWorker, procs).detach();

    setColor(2);
    std::wcout << L"  >> Signature scan running in background...\n";
    std::wcout << L"  >> Processes scored only after verification.\n\n";
    resetColor();

    while (true) {
        auto processes = getProcesses();
        bool monitorOpen = monitorToolOpen(processes);

        if (currentTick % 30 == 0)
            std::thread(signatureWorker, processes).detach();

        checkAnomalies(processes, monitorOpen);

        currentTick++;
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
    }

    return 0;
}