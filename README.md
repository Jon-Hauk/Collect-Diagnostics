# Collect-Diagnostics.ps1

A single-file, strictly read-only Windows diagnostic collector designed for async troubleshooting on Windows 10 and Windows 11. Runs on built-in Windows PowerShell 5.1 with zero external modules or installations.

## Verification Status

| Check | Status |
| --- | --- |
| Pester suite (PowerShell 5.1, Pester 3.4.0) | 21/21 passing |
| Live run, standard user, Windows 11 | Clean (no errors) |
| `-Redact` leak scan across all output files | 0 leaks (all local profile names, username, hostname) |
| Mark-of-the-Web download + `-ExecutionPolicy Bypass` | Verified |
| Live run as Administrator, Windows 11 (BitLocker, SMART paths) | Clean (no errors), 0 leaks |
| Windows 10 | Not yet verified live |

## Requirements

- Windows 10 or Windows 11
- Windows PowerShell 5.1 (built into Windows; no PowerShell 7 required)
- No external modules, no admin rights required (elevated sections log `SKIPPED: requires admin` cleanly)

## What It Collects

Running the script creates a `Diag_<yyyyMMdd_HHmm>` folder and packages it into `Diag_<yyyyMMdd_HHmm>.zip` next to the script:

| # | Section | Output File | Details Collected |
| --- | --- | --- | --- |
| 1 | OS | `01_os.txt` | Edition, version/display version, build + UBR, architecture, uptime, last 20 hotfixes, pending reboot checks |
| 2 | Hardware | `02_hardware.txt` | CPU specs & load, RAM total/used/free, fixed disk free %, physical disk health, SMART reliability counters (admin only) |
| 3 | Event Logs | `03_event_logs.csv` | `System` and `Application` logs, Error & Critical levels, last 7 days, top 25 by count (`LogName`, `ProviderName`, `EventId`, `Count`, sample message) |
| 4 | Network | `04_network.txt` | Network adapters, IP/subnet, default gateway, DNS servers, ICMP ping to `8.8.8.8`, DNS resolution test (`dns.google`) |
| 5 | Services | `05_services.csv` | Automatic-start services that are currently not running |
| 6 | Startup | `06_startup.txt` | Registry `Run`/`RunOnce` keys (`HKLM`/`HKCU`), user/common Startup folders, non-Microsoft scheduled tasks |
| 7 | Security | `07_security.txt` | Windows Defender status & signature age, Windows Firewall profile states, BitLocker protection status (admin only) |
| 8 | Processes | `08_processes.txt` | Top 10 processes by cumulative CPU seconds and top 10 by RAM working set |
| — | Summary | `summary.md` | One-line status per section plus automated issue flags |

## What It Never Touches

This script is strictly read-only on system state:

- **No registry writes** (only reads OS version, pending reboot indicators, and Run/RunOnce keys)
- **No service changes** (never starts, stops, restarts, or reconfigures services)
- **No system or user file modifications** (only creates the `Diag_<timestamp>` folder and `.zip` archive in the output directory)
- **No personal files or secrets** (never reads `Documents`, `Desktop`, browser profiles, saved passwords, Wi-Fi keys, environment secrets, or the Windows `Security` event log)
- **Minimal network activity** (the *only* outbound traffic is the Network section's 2-packet ping to `8.8.8.8` and a single DNS lookup for `dns.google`; nothing is uploaded anywhere)
- **Resilient execution** (each section is wrapped in `try/catch`; one failing or unprivileged section never halts the run)

## How to Run

1. Save `Collect-Diagnostics.ps1` to a folder (for example, `Downloads`).
2. Open **Windows PowerShell** in that folder (standard user works; run as Administrator if you also want SMART reliability counters and BitLocker status).
3. Run the collector (recommended `-Redact` mode):

```powershell
powershell -ExecutionPolicy Bypass -File .\Collect-Diagnostics.ps1 -Redact
```

`-ExecutionPolicy Bypass` applies to this single PowerShell process only — nothing is changed system-wide.

### Alternative: Unblock for Double-Click / Downloaded Files (Mark-of-the-Web)

Files downloaded from the internet carry Windows' Mark-of-the-Web (`Zone.Identifier`), which can trigger an execution policy block if you run or right-click **Run with PowerShell** / double-click directly. To remove that download flag first:

```powershell
Unblock-File -Path .\Collect-Diagnostics.ps1
```

### Other Run Options

```powershell
# Unredacted run (keeps real usernames, hostnames, MACs, and local IPs)
powershell -ExecutionPolicy Bypass -File .\Collect-Diagnostics.ps1

# Custom output folder
powershell -ExecutionPolicy Bypass -File .\Collect-Diagnostics.ps1 -Redact -OutputDirectory C:\Temp
```

Passing `-Redact` replaces usernames (all accounts under `C:\Users`, service `StartName` accounts, scheduled task `UserId` principals, and `DOMAIN\user` / `user@domain` patterns), computer hostname, domain names, MAC addresses, and private/link-local IP addresses (`10.x`, `172.16-31.x`, `192.168.x`, `169.254.x`, `fe80::`/`fd00::`) with stable anonymized tokens (`USER_1`, `HOST_1`, `DOMAIN_1`, `MAC_1`, `IP_1`, `IP6_1`) across all `.txt`, `.csv`, and `summary.md` outputs.

At completion, the script prints:

```text
Diagnostics archive created: C:\...\Diag_20261125_0035.zip
```

Send that `.zip` file back for diagnosis.

## Running Tests (Pester)

```powershell
Invoke-Pester -Script .\Collect-Diagnostics.Tests.ps1
```

In CI, add `-EnableExit` so the exit code reflects failures. Don't use it interactively, because it closes the PowerShell window.

## Sample `summary.md`

Illustrative example; values are not from a real machine.

```markdown
# Windows Diagnostic Summary

- **Collected**: 2026-11-25 00:35:12 -06:00
- **Host**: HOST_1
- **Elevation**: Standard User
- **Redacted**: True

## Section Status

| Section | File | Status | Summary |
| --- | --- | --- | --- |
| OS | `01_os.txt` | WARN | Microsoft Windows 11 Pro (Build 26100.9818), Uptime 4d 6h 18m, PendingReboot: True |
| Hardware | `02_hardware.txt` | WARN | AMD Ryzen 7 5800X; RAM 18.4/32 GB (57.5% used); Disks: C: 11.2% free, D: 62.0% free |
| Event Logs | `03_event_logs.csv` | WARN | 142 Error/Critical events in last 7 days across 8 source(s) |
| Network | `04_network.txt` | OK | Ping 8.8.8.8: 2/2 succeeded; DNS: Resolved dns.google -> 8.8.8.8, 8.8.4.4 |
| Services | `05_services.csv` | WARN | 2 automatic-start service(s) currently stopped |
| Startup | `06_startup.txt` | OK | 4 Run entries, 1 Startup folder items, 3 non-Microsoft scheduled tasks |
| Security | `07_security.txt` | OK | Defender: RTP=True, SigAge=1d; Firewall: Domain=True, Private=True, Public=True; BitLocker: SKIPPED: requires admin |
| Processes | `08_processes.txt` | OK | Total processes: 184; Top CPU: msedge (412.5s); Top RAM: msedge (1842.1 MB) |

## Flagged Issues

- Low disk space on C:: 11.2% free (threshold: < 15%)
- System has a pending reboot
- 2 automatic-start service(s) are stopped: MapsBroker, WSearch
- High error volume from "Disk": 68 events in the last 7 days (threshold: > 50)
```
