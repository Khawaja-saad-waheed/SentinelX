# SentinelX 🔍
### Real-time Malware Detection Engine for Windows

![C++](https://img.shields.io/badge/language-C++-blue)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## The Story

A few years ago I downloaded a game from a sketchy website. It worked fine — or so I thought.

For an entire month my laptop ran at 80°C with 100% CPU usage constantly. I assumed it was the game. It wasn't.

When I finally opened my OMEN gaming app I noticed something: the moment I opened Task Manager, CPU usage dropped to 1% instantly. The process was designed to hide the moment it detected monitoring software.

I had a cryptominer living in my system for a month and couldn't find it.

So I built SentinelX.

---

## What It Does

SentinelX monitors every running process on your Windows machine in real time and uses a **six-signal composite scoring system** to detect malicious behavior — without relying on virus definitions or signature databases.

It catches:
- 🔴 **Cryptominers** — sustained CPU abuse from headless unsigned processes
- 🔴 **Spyware & RATs** — abnormal network activity from invisible processes  
- 🔴 **Ransomware** — extreme disk I/O spikes from unsigned executables
- 🔴 **Evasion tactics** — processes that drop CPU usage the moment Task Manager opens (exactly what hit me)

---

## The Six Signals

| Signal | What It Catches |
|--------|----------------|
| Sustained high CPU | Miners, intensive background processes |
| High memory usage | Memory scrapers, injectors |
| High network activity | RATs, spyware phoning home |
| Abnormal disk I/O | Ransomware encrypting files |
| Headless process | No visible window while consuming resources |
| Unsigned executable | No verified publisher signature |

A process needs **2+ signals simultaneously** to get flagged. Single signals are ignored — this prevents false positives on legitimate software.

Signed processes (Chrome, games, Microsoft software) are **completely skipped** regardless of resource usage.

---

## Evasion Detection

SentinelX specifically watches for the tactic that got me:

If a process is running at high CPU and **drops significantly the moment Task Manager or Process Hacker opens** — it gets flagged immediately as an evasion attempt.

---

## How It Works

- Polls all running processes every 500ms
- Builds CPU baselines using Windows `GetProcessTimes` API
- Verifies executable signatures asynchronously via `WinVerifyTrust`
- Tracks 10-reading rolling history per process
- Scores each unsigned process against all six signals each tick

---

## Build Instructions

1. Clone the repo
2. Open `SentinelX.sln` in Visual Studio 2022
3. Set configuration to **Release x64**
4. Build → Run as Administrator (required for process inspection)

---

## Roadmap

- [ ] GUI frontend with real-time dashboard
- [ ] AI-powered threat report generation
- [ ] Export threat log to PDF
- [ ] Network destination analysis (flag known mining pool IPs)

---

## License

MIT — free to use, modify, and distribute.

If this helped you or you find it interesting, consider leaving a star ⭐

---

*Built after getting cryptomined for a month. Never again.*
