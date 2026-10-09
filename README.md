<div align="center">

<img src="https://img.shields.io/badge/KALI%20LINUX-557C94?style=for-the-badge&logo=kalilinux&logoColor=white" alt="Kali Linux" />
<img src="https://img.shields.io/badge/DEFENSIVE%20SECURITY-0F766E?style=for-the-badge&logo=owasp&logoColor=white" alt="Defensive security" />
<img src="https://img.shields.io/badge/STATIC%20ANALYSIS-1D4ED8?style=for-the-badge&logo=python&logoColor=white" alt="Static analysis" />
<img src="https://img.shields.io/badge/INCIDENT%20RESPONSE-7C3AED?style=for-the-badge" alt="Incident response" />

# 🛡️ Reverse-Shell Defensive Analysis Lab
By : Syed Muhammad Tayyab

### A practical, evidence-led investigation guide for aspiring SOC analysts and blue-team learners

**Preserve → Inspect → Correlate → Report**

[📘 PDF Field Guide](docs/reverse_shell_defensive_analysis_guide.pdf) · [📊 Editable PowerPoint](docs/reverse_shell_defensive_analysis_guide.pptx) · [🧭 MITRE ATT&CK](https://attack.mitre.org/) · [📚 NIST Incident Response](https://csrc.nist.gov/pubs/sp/800/61/r3/final)

<img src="https://img.shields.io/badge/Project%20Type-Blue%20Team%20Training-0F766E?style=flat-square" alt="Blue Team Training" />
<img src="https://img.shields.io/badge/Analysis-Static%20First-2563EB?style=flat-square" alt="Static First" />
<img src="https://img.shields.io/badge/Target-Kali%20Linux-557C94?style=flat-square&logo=kalilinux&logoColor=white" alt="Kali Linux" />
<img src="https://img.shields.io/badge/Status-Educational-F59E0B?style=flat-square" alt="Educational" />

</div>

---

> [!CAUTION]
> **Defensive training repository only.** The case study describes a Python script designed to accept remote data, pass it to a local shell, return output, and attempt to delete its own file. Do **not** run the sample, launch a listener for it, package it as an executable, conceal it, or test it on a device or network without explicit written authorization. The operational payload is intentionally not included. Instead, `samples/payload.py` is a harmless simulator that prints a list of indicators for training; it does not open sockets, execute shell commands, or delete files. This repository focuses on safe static analysis, evidence handling, telemetry review, and incident reporting.

## 📌 Table of contents

- [Overview](#-overview)
- [Learning objectives](#-learning-objectives)
- [Repository contents](#-repository-contents)
- [Prerequisites](#-prerequisites)
- [Quick start on Kali Linux](#-quick-start-on-kali-linux)
- [Step 1 — Preserve and hash the archive](#step-1--preserve-and-hash-the-archive)
- [Step 2 — Inspect the ZIP without running its contents](#step-2--inspect-the-zip-without-running-its-contents)
- [Step 3 — Review source code as text](#step-3--review-source-code-as-text)
- [Safe `payload.py` training simulator](#-safe-payloadpy-training-simulator)
- [Step 4 — Build a telemetry hypothesis](#step-4--build-a-telemetry-hypothesis)
- [Step 5 — Investigate logs on an authorized endpoint](#step-5--investigate-logs-on-an-authorized-endpoint)
- [Step 6 — Write the finding](#step-6--write-the-finding)
- [Practice exercise](#-practice-exercise)
- [Important technical notes](#-important-technical-notes)
- [MITRE ATT&CK mapping](#-mitre-attck-mapping)
- [Further reading](#-further-reading)
- [Troubleshooting](#-troubleshooting)
- [Responsible use](#-responsible-use)
- [Clone this repository](#-clone-this-repository)
- [Suggested repository name and GitHub topics](#-suggested-repository-name-and-github-topics)

## 🔍 Overview

This lab helps learners investigate a suspicious Python ZIP file using a **static-first workflow**. It is intended for cybersecurity students, junior SOC analysts, incident responders, and blue-team practitioners who want to practice describing behavior using evidence rather than assumptions.

The case study describes several high-signal patterns an analyst should look for in an untrusted sample:

| Code pattern | What it can mean | What an analyst should validate |
|---|---|---|
| `socket.connect(...)` | Attempts an outbound network connection | Destination, port, timestamp, process owner, and network context |
| `recv(...)` | Receives data from a peer | Whether incoming data is treated as commands or ordinary application data |
| `subprocess.Popen(..., shell=True)` | Starts a command through a system shell | Parent/child process tree, command line, user context, and timing |
| `send(...)` | Sends data over a socket | Direction, volume, destination, and possible correlation with process output |
| `os.remove(__file__)` | Attempts to remove the running script's path | File-system or EDR deletion events; an attempt does not prove deletion succeeded |
| Broad exception handling | Suppresses error details | Whether errors are hidden and whether telemetry exists outside the application |

**No single function proves malicious intent by itself.** Assess the combination of behaviors, the process lineage, the destination, the surrounding events, and the business context.

## 🎯 Learning objectives

By completing the workflow, you should be able to:

- Preserve an artifact and record a SHA-256 hash.
- Inspect ZIP members and review Python source **without executing it**.
- Identify network, command-execution, and file-deletion behaviors in source code.
- Form a detection hypothesis from process, network, and file telemetry.
- Separate observed facts from assumptions in an analyst report.
- Explain technical limitations and recommend proportionate incident-response steps.

## 📁 Repository contents

```text
reverse-shell-defensive-analysis-lab/
├── README.md
├── docs/
│   ├── reverse_shell_defensive_analysis_guide.pdf
│   └── reverse_shell_defensive_analysis_guide.pptx
├── samples/
│   └── payload.py     # Harmless simulator; not a working reverse shell
├── evidence/       # Keep local case evidence out of public Git repositories
├── reports/        # Store sanitized, non-sensitive reports here
└── templates/      # Add your sanitized report templates here
```

The `evidence/` folder is for **local analysis only**. Do not commit real malware samples, customer information, credentials, internal hostnames, private IP inventories, or other sensitive artifacts to a public repository. Keep the PDF and PowerPoint in `docs/` so the links at the top work in GitHub.

## 🧰 Prerequisites

- Kali Linux or another Linux analysis VM.
- A terminal and a standard, non-administrator user account.
- `unzip`, `file`, `coreutils` (for `sha256sum`), `grep`, and `less`.
- A suspicious ZIP supplied through an approved training or incident-response process.
- An isolated lab or analysis workstation. Static inspection is the recommended first pass.

Install the inspection utilities on Kali Linux:

```bash
sudo apt update
sudo apt install -y unzip file coreutils grep less git
```

> Package installation requires administrator approval on your own lab machine. Do not install tools or change settings on systems you do not administer.

## 🚀 Quick start on Kali Linux

### 1. Create a local case folder

Use a case-specific directory so that evidence, notes, and output stay organized. Replace `CASE-001` with your organization's approved case identifier.

```bash
CASE="$HOME/cases/CASE-001"
mkdir -p "$CASE/evidence" "$CASE/notes" "$CASE/output"
printf 'Case ID: CASE-001\nAnalyst: YOUR_NAME\nTimezone: YOUR_TIMEZONE\n' \
  > "$CASE/notes/case-info.txt"
```

### 2. Put the supplied ZIP in the case folder

The next commands assume the authorized sample is named `update.zip` in your current directory. Adjust the filename and path if your evidence has a different name.

```bash
cp --preserve=timestamps ./update.zip "$CASE/evidence/update.zip"
chmod a-w "$CASE/evidence/update.zip"
```

`chmod a-w` removes write permission for all classes on this copied file; do not rely on file permissions alone as an evidence-integrity control. Follow your organization's evidence-handling procedure and retain the original safely.

### 3. Record basic file details and hash

```bash
file "$CASE/evidence/update.zip" \
  | tee "$CASE/notes/file-type.txt"

stat "$CASE/evidence/update.zip" \
  | tee "$CASE/notes/file-stat.txt"

sha256sum "$CASE/evidence/update.zip" \
  | tee "$CASE/notes/sha256.txt"
```

Keep the full hash in your notes. A hash identifies the exact bytes you examined; it does not by itself establish that a file is malicious or benign.

## Step 1 — Preserve and hash the archive

Before inspecting a suspicious artifact, record:

- Original file name and acquisition source.
- Acquisition date/time and timezone.
- Case ID and analyst identifier.
- File type, file size, and SHA-256 hash.
- Storage path and handling notes.

Review the files you recorded:

```bash
cat "$CASE/notes/file-type.txt"
cat "$CASE/notes/sha256.txt"
```

For a minimal chain-of-custody note, open a text editor:

```bash
nano "$CASE/notes/triage-notes.md"
```

In Nano, save with **Ctrl+O**, press **Enter**, and exit with **Ctrl+X**. Record commands run, timestamps, observations, and any transfer of evidence. Never include passwords or other secrets.

## Step 2 — Inspect the ZIP without running its contents

List member names and metadata first. Do not double-click the archive or run a script inside it.

```bash
unzip -l "$CASE/evidence/update.zip" \
  | tee "$CASE/notes/zip-listing.txt"
```

Look for unexpected names, nested archives, unusually large members, and mismatches between file extensions and actual types. If the expected member name differs from `payload.py`, use the name shown by the listing in the next step.

## Step 3 — Review source code as text

The following commands **read** the `payload.py` archive member and save it as a plain-text review copy. They do not execute Python code.

```bash
unzip -p "$CASE/evidence/update.zip" payload.py \
  > "$CASE/notes/payload_static_review.py.txt"

less "$CASE/notes/payload_static_review.py.txt"
```

Search the text for high-signal review cues:

```bash
grep -nE 'socket|connect|recv|Popen|shell=True|send|os\.remove|except' \
  "$CASE/notes/payload_static_review.py.txt" \
  | tee "$CASE/notes/source-indicators.txt"
```

Search for embedded network indicators or paths:

```bash
grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}|PORT|https?://|/tmp/|/var/tmp/' \
  "$CASE/notes/payload_static_review.py.txt" \
  | tee "$CASE/notes/embedded-indicators.txt"
```

These are triage searches, not a verdict. A matching keyword is only a lead; document the surrounding source context and validate it against telemetry. The example address `192.168.1.100` is in private IPv4 address space and is not, by itself, proof of attacker identity or public Internet infrastructure.

> [!WARNING]
> Do not run `payload.py` extracted from an untrusted archive, start a listener for it, package it as an executable, rename it for stealth, or deploy it to another machine. The working operational payload is intentionally excluded. The repository's `samples/payload.py` is a separate, harmless simulator.

## 🧪 Safe `payload.py` training simulator

You were right to look for a Python file. This repository now includes [`samples/payload.py`](samples/payload.py), a **non-operational training substitute**. It prints analyst notes about suspicious code patterns, but it does not import networking or process-execution libraries, make connections, run shell commands, or delete any files. It is not the original live payload.

### Review and run the simulator on Kali Linux

```bash
# From the repository root, inspect it as text first
sed -n '1,220p' samples/payload.py

# Run the harmless simulator (prints indicators only)
python3 samples/payload.py

# Save its synthetic output for your notes
python3 samples/payload.py | tee simulator-output.txt
```

### Full source of `samples/payload.py`

```python
#!/usr/bin/env python3
"""Harmless reverse-shell indicator simulator for blue-team training.

This is NOT a reverse shell and does not reproduce the operational payload.
It performs no network communication, executes no system commands, and does
not read or delete files. It only prints a static list of code patterns that
an analyst may encounter during source review.
"""

from __future__ import annotations

import json

INDICATORS = [
    {
        "source_pattern": "socket.connect((SERVER_IP, SERVER_PORT))",
        "analyst_note": (
            "Could indicate an outbound connection attempt; validate the actual "
            "destination, port, process, timestamp, and network context."
        ),
    },
    {
        "source_pattern": "recv(...)",
        "analyst_note": (
            "Inspect how received bytes are interpreted and whether they are "
            "treated as commands or ordinary application data."
        ),
    },
    {
        "source_pattern": "subprocess.Popen(..., shell=True)",
        "analyst_note": (
            "Review for shell invocation and correlate with process-tree and "
            "command-line telemetry. This simulator does not call Popen."
        ),
    },
    {
        "source_pattern": "send(...)",
        "analyst_note": (
            "Could indicate data being sent to a peer; inspect direction, "
            "destination, volume, and process attribution."
        ),
    },
    {
        "source_pattern": "os.remove(__file__)",
        "analyst_note": (
            "Could indicate an attempt to delete the script path; validate "
            "file-system telemetry. This simulator deletes nothing."
        ),
    },
]


def main() -> int:
    """Print synthetic indicators without performing any of their behaviors."""
    print("SAFE TRAINING SIMULATOR")
    print("Network access: none | Shell execution: none | File deletion: none\n")
    print(json.dumps({"simulation_only": True, "indicators": INDICATORS}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

**Important:** This is deliberately not the operational reverse-shell code described in the case study. Use it to practice reading source, discussing indicators, and writing detection hypotheses.

## Step 4 — Build a telemetry hypothesis

If the script may have executed on an endpoint, investigate logs collected by your approved endpoint detection and response (EDR), host audit, firewall, DNS, proxy, or network-monitoring tools.

Look for a time-correlated sequence such as:

1. An archive or script appears on disk.
2. A Python interpreter is launched, with its parent process and command line recorded.
3. The process attempts an outbound TCP connection to a configured address and port.
4. A shell or command interpreter appears as a child process of Python.
5. A file-deletion event follows for the script path.

The sequence above is a **hypothesis and illustrative pattern**, not proof that the supplied script ran. Missing events may reflect telemetry that was never enabled or retained.

### What to collect

| Data source | Useful evidence |
|---|---|
| Endpoint process telemetry | Image path, command line, parent/child relationship, user, process ID, timestamp |
| Network telemetry | Source/destination IP and port, connection time, firewall action, process attribution if available |
| File telemetry | Archive/script path, creation and deletion times, hash, originating process |
| Authentication and identity logs | User context and nearby logon activity, where relevant |
| EDR alerts | Detection name, alert ID, sensor state, associated entities, and raw event references |

Avoid alerting on “Python” or port `9999` alone. Establish a baseline, validate the destination and context, and correlate multiple data sources.

## Step 5 — Investigate logs on an authorized endpoint

Only run log searches on a system you own or are explicitly authorized to investigate. The examples below are read-only searches; available log sources vary by configuration.

### Linux: search available text logs

```bash
sudo grep -RniE 'payload\.py|192\.168\.1\.100|9999' \
  /var/log/syslog /var/log/auth.log 2>/dev/null \
  | tee "$CASE/notes/linux-log-matches.txt"
```

A lack of results does not prove the activity did not occur. These files may not exist on the system, and ordinary Linux logs do not necessarily record every process creation or outbound connection. Prefer configured audit, EDR, firewall, and network telemetry.

### Linux: inspect the current process/network state

If you are responding to a live endpoint, follow the incident-response playbook before issuing commands that could alter evidence or tip off an intruder. When permitted, these read-only commands can provide a limited current-state view:

```bash
ps -eo user,pid,ppid,lstart,args --forest \
  | grep -E '[p]ython|[b]ash|[s]h|payload\.py'

ss -tpn
```

These commands show only current processes or connections and cannot reconstruct historical activity by themselves.

### Windows: search Sysmon events with PowerShell

If Sysmon is installed and its relevant event collection is configured, an authorized investigator can search recent Sysmon event messages. Run PowerShell as permitted by your organization's policy:

```powershell
$since = (Get-Date).AddHours(-24)
$patterns = 'payload\.py|192\.168\.1\.100|9999|python\.exe'

Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $since
} -ErrorAction SilentlyContinue |
    Where-Object { $_.Message -match $patterns } |
    Select-Object TimeCreated, Id, ProviderName, Message |
    Format-List |
    Out-File -Encoding utf8 .\sysmon-triage.txt
```

Review event details and correlate process-creation events (commonly Sysmon Event ID 1), network-connection events (commonly Event ID 3 when enabled), and file events if configured. Event availability depends on Sysmon configuration and retention. A string match alone is not a confirmed detection.

## Step 6 — Write the finding

Keep the report concise, evidence-led, and reproducible. Separate what the source code intends to do from what endpoint evidence proves happened.

Use this template in your case notes or create a sanitized report under `reports/`:

```markdown
# Defensive Analysis Report

- Case ID: CASE-001
- Analyst: YOUR_NAME
- Date/time and timezone: YYYY-MM-DD HH:MM TZ
- Artifact name: update.zip
- SHA-256: <recorded hash>
- File type and size: <observed values>
- Acquisition source: <authorized source>

## Summary
<One paragraph describing the assessment and confidence.>

## Observed facts
- <Evidence item and source/log reference>
- <Timestamp and timezone>
- <Process, network, or file event actually observed>

## Source-code observations
- <Relevant source behavior and line reference>
- <Interpretation and limitations>

## Assessment
- Classification: <suspected / likely / confirmed, with rationale>
- Confidence: <low / medium / high, with basis>
- Alternatives considered: <benign explanation or telemetry gap>

## Recommended actions
- <Containment or scoping action under approved policy>
- <Evidence to preserve>
- <Credential review / recovery action if warranted>

## Open questions
- <What remains unproven and what evidence would resolve it>
```

Prefer precise language such as:

> “The source is designed to accept remote data and pass it to a local shell. Source code alone does not establish that it executed on an endpoint.”

Avoid unsupported claims such as “it bypasses administrator controls,” “the attacker is identified,” or “the file definitely self-destructed.”

## 🧪 Practice exercise

The following is **synthetic training data** for report-writing practice. It is not the output of a running payload.

| Time | Source | Illustrative observation | Analyst next step |
|---|---|---|---|
| 09:40:02 | File telemetry | `update.zip` appears in Downloads | Preserve evidence and hash the archive |
| 09:40:17 | Process telemetry | Python is launched by a file manager | Review command line, parent, user, and hash |
| 09:40:18 | Network telemetry | Outbound TCP to `192.168.1.100:9999` | Confirm local network topology and process attribution |
| 09:40:20 | Process telemetry | A shell process appears under Python | Validate parent/child relationship and command line |
| 09:40:48 | File telemetry | A `payload.py` deletion event is recorded | Correlate file path, process, and timestamp |

Answer these questions in your report:

1. Which events have the highest investigative value, and why?
2. What other evidence would you request before making a severity decision?
3. Which conclusions are directly supported by the timeline?
4. What remains unproven, including whether the events share the same cause?
5. What containment, scoping, or recovery steps would be proportionate under the incident-response playbook?

## 🧠 Important technical notes

- **Privileges:** A script normally inherits the permissions of the account that launches it. This code does not magically bypass UAC or acquire administrator/root privileges.
- **Interactive shell:** The simple receive/execute/read loop is not a robust terminal implementation. Blocking reads and missing protocol framing can make it unreliable.
- **Self-deletion:** `os.remove(__file__)` attempts to remove the script path; an attempted deletion is not proof it succeeded. Logs, caches, backups, and file-system records may still retain evidence.
- **Private IP address:** `192.168.1.100` is within private IPv4 address space. Its meaning depends on network context and it does not establish attribution.
- **Telemetry gaps:** An empty log search is not proof of absence. Validate data-source coverage, policy, clock settings, and retention.

## 🧭 MITRE ATT&CK mapping

Use ATT&CK mappings as a way to organize observed behavior, not as a substitute for evidence:

| Technique | Why it may be relevant | Reference |
|---|---|---|
| **T1059.006 — Command and Scripting Interpreter: Python** | The sample is written in Python and is intended to use it as an execution interpreter | [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/006/) |
| **T1059.004 — Command and Scripting Interpreter: Unix Shell** | The source passes received data to a shell using `shell=True`; validate platform and runtime evidence before assigning this to an incident | [MITRE ATT&CK](https://attack.mitre.org/techniques/T1059/004/) |

Do not force a mapping when telemetry does not support it. Document the exact behavior and evidence for every technique you report.

## 📚 Further reading

- [MITRE ATT&CK — Python (T1059.006)](https://attack.mitre.org/techniques/T1059/006/)
- [MITRE ATT&CK — Unix Shell (T1059.004)](https://attack.mitre.org/techniques/T1059/004/)
- [Microsoft Sysmon event documentation](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [NIST SP 800-61 Rev. 3 — Incident Response Recommendations](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Kali Linux Documentation](https://www.kali.org/docs/)
- [GitHub Docs — About READMEs](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes)

## 🛠️ Troubleshooting

**`unzip: cannot find or open update.zip`**

Check your current directory and the file path:

```bash
pwd
ls -lah
find "$HOME" -maxdepth 4 -type f -name 'update.zip' 2>/dev/null
```

Update the `cp` command to point to the actual evidence location. Do not download or execute unknown files just to complete the exercise.

**`caution: filename not matched: payload.py`**

The archive may use a different member name. List it first and use the exact member path:

```bash
unzip -l "$CASE/evidence/update.zip"
```

**`sha256sum` or `unzip` is not installed**

On Kali Linux, install the needed system utilities through your normal package-management process:

```bash
sudo apt update
sudo apt install -y coreutils unzip
```

**No log matches are returned**

Confirm the searched file exists, check event collection and retention, and query approved EDR/network sources. Lack of a match is not proof that no execution occurred.

## 🤝 Responsible use

This project is for authorized education, threat analysis, blue-team detection practice, and incident-response training. You are responsible for complying with applicable laws, workplace policy, and any lab rules.

- Use only artifacts from approved training sources or authorized investigations.
- Prefer static analysis and synthetic telemetry for portfolio exercises.
- Keep lab networks isolated and use snapshots for approved dynamic analysis.
- Never publish real customer data, private logs, secrets, credentials, or unapproved samples.
- Preserve evidence before cleanup when required by the incident-response process.
- If an endpoint may be compromised, follow your organization's escalation and containment playbook.

## 📥 Clone this repository

Once you publish this project to GitHub, anyone can clone it using the repository URL. Replace `YOUR_GITHUB_USERNAME` with the account that owns the repository.

```bash
git clone https://github.com/YOUR_GITHUB_USERNAME/reverse-shell-defensive-analysis-lab.git
cd reverse-shell-defensive-analysis-lab
```

To update an existing local copy later:

```bash
git pull
```

**Note:** The URL above is a template, not a live repository link. It will work only after a GitHub repository with this exact name is created under your username and the files are pushed to it.

### Publish it to GitHub

From the project directory, after creating an empty repository on GitHub with the suggested name:

```bash
git init
git add README.md .gitignore docs/ templates/ samples/payload.py evidence/README.txt reports/README.txt
git commit -m "Add defensive reverse-shell analysis lab guide"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/reverse-shell-defensive-analysis-lab.git
git push -u origin main
```

Review `git status` and `git diff --cached` before pushing. The example stages the README, guide documents, safe simulator, and placeholder files, not local case data under `evidence/` or `reports/`. Never force-add sensitive files.

## 🌟 Suggested repository name and GitHub topics

### Recommended repository name

**`reverse-shell-defensive-analysis-lab`**

Why this name works: it is descriptive, readable, searchable, and makes the defensive training purpose clear. It avoids presenting the project as a payload builder or deployment toolkit.

**Repository description**

> A safe blue-team lab guide for static triage and telemetry-based investigation of reverse-shell-like Python behavior, with Kali Linux commands, evidence handling, and incident-report templates.

**Suggested GitHub topics**

`cybersecurity` · `blue-team` · `defensive-security` · `malware-analysis` · `kali-linux` · `incident-response` · `mitre-attack` · `soc-analyst` · `static-analysis` · `sysmon` · `threat-hunting`

**Suggested GitHub About website:** link to your published project page only after you have created one. Until then, the PDF and PowerPoint links at the top point to files committed in this repository.

---

<div align="center">

**Built for learning. Guided by evidence. Focused on defense.**

<sub>Educational resource · Static-first workflow · Validate all findings with authorized telemetry</sub>

</div>
