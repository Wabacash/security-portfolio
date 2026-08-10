# Windows Endpoint Hardening Review — TryHackMe Lab Environment (2026)

## Objective

Conduct a hardening review of a Windows endpoint to identify misconfigurations, insecure service defaults, and exposed sensitive artifacts that would represent risk in a production environment. The review was performed against a lab-provisioned VM (TryHackMe "Windows Hardening" room) to build practical skills in configuration auditing, registry/service inspection, and Windows Defender policy review — translated here into findings and remediation guidance consistent with a real endpoint security assessment.

## Scope

- Local Windows services configuration (Services console)
- Registry configuration (HKLM, HKCU)
- Windows Defender Antivirus exclusion policy
- Local file system permissions (NTFS ACLs)
- BitLocker disk encryption key management
- Desktop/user-profile artifact review

## Methodology

Assessment was performed using native Windows tooling only (no third-party scanners), reflecting a constrained-access scenario such as a locked-down corporate endpoint or an incident response engagement with limited tool availability:

- `services.msc` — service startup configuration review
- `regedit` — registry key inspection
- `gpedit.msc` — Group Policy configuration review (Administrative Templates → Windows Components → Microsoft Defender Antivirus)
- `cmd.exe` (`findstr`, `dir`, `takeown`, `icacls`, `type`) — file system search, permission review, and remediation, used in place of PowerShell after PowerShell became unresponsive on the host
- `manage-bde` — BitLocker key protector inspection

---

## Findings

### Finding 1 — Non-Standard Service Startup Configuration (App Readiness)

**Description:** The *App Readiness* service was found configured with a Manual (Trigger Start) startup type.

**Risk/Impact:** Trigger-started services activate automatically under specific system conditions (e.g. app installation events) without requiring explicit user or admin action. While this is Microsoft's own default for this particular service, in a hardening review any trigger-started or auto-starting service should be validated against the organization's baseline — unnecessary trigger-start services expand the attack surface by giving a process a legitimate, low-visibility way to launch without direct invocation.

**Remediation:**
```
sc config AppReadiness start= disabled
```
Disable only if App Readiness functionality (app provisioning/installation features) is not required in the environment; validate against business need before disabling in production.

---

### Finding 2 — Unmanaged/Test Registry Key Present Under Inspected Path

**Description:** A registry key named `tryhackme` was identified during registry review, with a default value of `0`.

**Risk/Impact:** The presence of an unexplained, non-Microsoft registry key is significant from a hardening standpoint regardless of its actual content — it indicates either leftover test/debug tooling, a misconfiguration during provisioning, or in a real-world scenario, a potential persistence marker left by an attacker or red-team engagement. Unidentified registry artifacts should always be treated as suspicious until attributed to a known, authorized source.

**Remediation:**
```
reg delete "HKCU\<path>\tryhackme" /f
```
(Confirm full key path and ownership before deletion in a live environment; export the key first for evidence retention if this were a real incident: `reg export "HKCU\<path>\tryhackme" tryhackme_backup.reg`)

---

### Finding 3 — Broken NTFS Permissions on Diagnostic Log File

**Description:** A file (`flag.txt.txt`) located in `C:\ProgramData\Microsoft\Diagnosis` was inaccessible even to a locally authenticated user attempting to read, take ownership of, or modify permissions on the file (`takeown` and `icacls` both returned Access is Denied).

**Risk/Impact:** Overly restrictive or broken ACLs on files inside system diagnostic directories can indicate either intentional hardening (positive) or accidental misconfiguration during imaging/provisioning (negative) — either way, it's a deviation from Windows' expected default permission set for `ProgramData\Microsoft\Diagnosis` and should be explicitly documented rather than left ambiguous. In an operational environment, broken ACLs on diagnostic paths can also mask log tampering, since neither admins nor the built-in diagnostic services can reliably read/write those files.

**Remediation:**
```
icacls "C:\ProgramData\Microsoft\Diagnosis\flag.txt.txt" /reset
icacls "C:\ProgramData\Microsoft\Diagnosis\flag.txt.txt" /grant Administrators:F
```
Reset to inherited defaults from the parent directory, then explicitly re-grant only the access levels required — avoid granting broad `Everyone` or `Users` write access to diagnostic paths.

---

### Finding 4 — Windows Defender Extension Exclusion (.ps)

**Description:** Windows Defender Antivirus was configured (via registry, under `HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions`) to exclude the `.ps` file extension from scanning. This was not set via Group Policy (Group Policy Editor showed all Defender exclusion policies as "Not configured"), indicating the exclusion was applied directly to the registry, bypassing centralized policy management.

**Risk/Impact:** This is the most significant finding in the review. Excluding script-related extensions from AV scanning is a well-documented technique used by attackers and red teams to stage payloads without triggering real-time detection. Because the exclusion was applied outside of Group Policy, it would not be visible to an administrator reviewing GPO-based Defender configuration — making it a stealthy evasion vector as well as a governance gap (local exclusions can silently override or supplement centrally managed policy).

**Remediation:**
```
reg delete "HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions" /v ".ps" /f
```
Follow up by auditing all other locally-configured Defender exclusions on the host, and enforce exclusion management centrally via Group Policy or Microsoft Defender for Endpoint / Intune policy so local registry changes cannot silently override the org baseline:
```
Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions"
```
(for verification once PowerShell access is restored)

---

### Finding 5 — BitLocker Recovery Key Stored Locally in Plaintext

**Description:** A BitLocker recovery key (48-character format, ending in `322773`) was found stored locally on the same disk it protects, rather than escrowed to Active Directory, Entra ID, or a dedicated key management solution.

**Risk/Impact:** This defeats the primary security purpose of BitLocker. If the recovery key is retrievable from the same machine/disk it's meant to protect, an attacker with local or physical access to the device can recover the key and decrypt the volume, fully bypassing the encryption control. This is a critical finding — encryption key material must never be stored on the asset it protects.

**Remediation:**
- Immediately rotate the compromised recovery key:
```
manage-bde -protectors -delete C: -type RecoveryPassword
manage-bde -protectors -add C: -RecoveryPassword
```
- Escrow the new key to Active Directory or Entra ID:
```
manage-bde -protectors -get C:
BackupToAAD-BitLockerKeyProtector -MountPoint "C:" -KeyProtectorId "<GUID>"
```
- Remove the locally stored key file entirely and confirm no residual copies exist in Recycle Bin, temp folders, or backup locations.

---

### Finding 6 — Unsecured Backup File on User Desktop

**Description:** A backup file with a `.bkf` extension was found stored directly on the user's Desktop.

**Risk/Impact:** Backup files often contain sensitive system or user data (registry hives, user profile data, credentials cache, etc. depending on backup scope) and storing them in an easily accessible, unencrypted user-facing location increases exposure risk — particularly if the endpoint is shared, lost, or compromised. Desktop storage also suggests no formal backup retention/location policy is being followed.

**Remediation:**
- Relocate backup files to a secured, access-controlled backup location (network share with restricted ACLs, or dedicated backup solution) rather than local user-profile paths.
- If retained locally, encrypt the file and restrict NTFS permissions to authorized accounts only:
```
icacls "C:\Users\<user>\Desktop\<file>.bkf" /inheritance:r /grant Administrators:F
```
- Establish a backup handling policy specifying approved storage locations and retention.

---

## Summary Table

| # | Finding | Severity | Category |
|---|---------|----------|----------|
| 1 | App Readiness service — non-default trigger-start config | Low | Service Hardening |
| 2 | Unattributed registry key (`tryhackme`) | Medium | Persistence / Config Drift |
| 3 | Broken NTFS ACLs on diagnostic log file | Medium | Access Control |
| 4 | Defender `.ps` extension exclusion (local, non-GPO) | **High** | AV Evasion / Governance Gap |
| 5 | BitLocker recovery key stored locally in plaintext | **Critical** | Encryption Key Management |
| 6 | Unsecured `.bkf` backup file on Desktop | Medium | Data Exposure |

## Conclusion

This review identified six configuration and hardening gaps ranging from low-severity service defaults to a critical encryption key management failure. The most concerning findings — the non-GPO Defender exclusion and the locally-stored BitLocker recovery key — both represent controls that were technically "present" (AV was running, the disk was encrypted) but rendered ineffective through misconfiguration. This reinforces a core hardening principle: security controls must be validated end-to-end, not just confirmed as enabled, since local overrides and key mismanagement can silently undermine centrally enforced policy.

*Environment: TryHackMe lab VM, used for hands-on hardening/audit skill-building.*