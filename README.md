# TaskSchedule Checker

**A read-only Windows Scheduled Task auditing and baseline comparison tool for cyber threat intelligence, threat hunting, and incident response.**

TaskSchedule Checker (`cti_scheduled_tasks.py`) inventories Windows Task Scheduler entries, highlights task configurations that merit review, and compares subsequent scans against a trusted baseline to identify **new, modified, or removed tasks**.

Scheduled tasks have many legitimate uses, but adversaries can also abuse them for persistence or execution. This project supports investigation of **MITRE ATT&CK [T1053.005 — Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)**. Its findings are investigative leads, **not proof of compromise**.

> [!IMPORTANT]
> The project is **read-only**. It does not create, run, disable, delete, or otherwise modify scheduled tasks. It can enumerate only the tasks accessible to the account running it.

## Features

- Recursively inventories accessible scheduled tasks, including tasks marked `Hidden=true`.
- Displays task paths, states, enabled/hidden status, authors, execution accounts, run levels, and registration metadata.
- Extracts task actions, command-line arguments, working directories, and triggers.
- Includes last-run and next-run information where available.
- Flags review indicators such as execution from commonly user-writable locations, interpreter/dual-use utilities, potentially suspicious command arguments, and hidden tasks.
- Creates a JSON baseline of a known, trusted system state.
- Identifies **new**, **modified**, and **removed** tasks relative to the baseline; displays relevant changed fields for modified tasks.
- Exports results as **CSV** or **JSON**.
- Warns when permission or parsing errors make a scan incomplete; avoids reporting removals from incomplete comparisons.
- Requires no third-party Python packages.

## Requirements

- Windows 10/11 or Windows Server with Windows Task Scheduler.
- Python **3.9 or newer**.
- Windows PowerShell **5.1** (`powershell.exe`), available on supported Windows installations.
- An account with sufficient permissions to inspect the relevant scheduled tasks. **Run the terminal as Administrator** for the broadest visibility.

The tool uses the built-in **Task Scheduler COM API**, invoked through Windows PowerShell, and Python's standard library. It does **not** require `pip install`.

## Installation

Clone the repository:

```powershell
git clone https://github.com/CE47/TaskSchedule_Checker.git
cd TaskSchedule_Checker
```

Alternatively, download `cti_scheduled_tasks.py` into a working directory.

Confirm that Python is installed:

```powershell
py -3 --version
```

Open an elevated **PowerShell** or **Command Prompt** session before scanning.

## Quick start

### 1. List all accessible scheduled tasks

```powershell
py -3 cti_scheduled_tasks.py list
```

The output includes each task's path, configured execution details, triggers, and review indicators. The default command is `list`, so running the script without a subcommand also lists tasks.

### 2. Show only tasks with review indicators

```powershell
py -3 cti_scheduled_tasks.py list --review-only
```

These indicators are heuristic triage aids. Legitimate administrative tasks frequently use PowerShell, command interpreters, or hidden-task settings.

### 3. Search task paths and actions

```powershell
py -3 cti_scheduled_tasks.py list --match powershell
```

The match is case-insensitive and searches task paths and displayed action commands.

### 4. Create a trusted baseline

```powershell
py -3 cti_scheduled_tasks.py baseline
```

By default, this saves `scheduled_tasks_baseline.json` in the current directory. Establish a baseline only **after validating the endpoint's state**. The script refuses to overwrite an existing baseline unless `--force` is explicitly supplied.

### 5. Compare current tasks with the baseline

```powershell
py -3 cti_scheduled_tasks.py check
```

Changes are grouped as:

| Finding | Meaning |
| --- | --- |
| `NEW` | A task path is present now but absent from the baseline. |
| `MODIFIED` | A task's definition differs from the baseline; relevant changed fields are shown. |
| `REMOVED` | A previously recorded task is absent from a complete current scan, and the baseline was complete. |

A `NEW` finding means **new relative to the saved baseline**, not necessarily that the task was created recently. A changed task can also reflect a legitimate software update or administrative action.

## Exporting reports

Export a full task inventory to CSV:

```powershell
py -3 cti_scheduled_tasks.py list --csv scheduled_tasks.csv
```

Export a filtered inventory to JSON:

```powershell
py -3 cti_scheduled_tasks.py list --review-only --json review_tasks.json
```

Export a baseline comparison:

```powershell
py -3 cti_scheduled_tasks.py check --json task_changes.json --csv task_changes.csv
```

**Note:** In `check` mode, the CSV includes **new and modified tasks**; the JSON report additionally records removed tasks, warnings, and whether removed-task comparison was skipped.

## Command-line reference

```text
py -3 cti_scheduled_tasks.py [list|baseline|check] [options]
```

| Option | Description |
| --- | --- |
| `--baseline PATH` | Use a baseline file other than the default `scheduled_tasks_baseline.json`. |
| `--csv PATH` | Export displayed tasks (or new/modified comparison findings) as CSV. |
| `--json PATH` | Export the inventory or comparison report as JSON. |
| `--review-only` | With `list`, display only tasks with review indicators. |
| `--match TEXT` | With `list`, filter task paths and actions using a case-insensitive search. |
| `--force` | With `baseline`, deliberately replace an existing baseline. |
| `--allow-partial` | With `baseline`, permit saving despite enumeration warnings; **not recommended**. |
| `-h`, `--help` | Display command-line help. |

### Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Completed successfully; for `check`, no differences were found. |
| `10` | `check` completed and found one or more new, modified, or removed tasks. |
| `2` | Error or incomplete scan; inspect warnings and do not treat the comparison as complete. |

The nonzero code `10` can be used by monitoring workflows, but it is **not by itself an indication of malicious activity**.

## What gets flagged for review?

The heuristic review indicators include:

- Task actions referencing commonly user-writable directories, such as `AppData`, `Temp`, `Downloads`, or `Users\Public`.
- Actions invoking interpreters or dual-use Windows utilities, such as `powershell.exe`, `cmd.exe`, `wscript.exe`, `mshta.exe`, `certutil.exe`, or `wmic.exe`.
- Command arguments containing patterns such as encoded commands, download URLs, or PowerShell execution-related keywords.
- Tasks configured with `Hidden=true`.

A finding should be assessed alongside the task's **purpose, owner, executable path, command arguments, trigger, execution account, and surrounding endpoint telemetry**. The tool does not automatically assign a risk score or declare a task malicious.

## Suggested investigation workflow

1. **Inventory:** Run `list` from an elevated terminal and inspect enumeration warnings.
2. **Baseline:** Save a snapshot only after verifying the system is in an acceptable state.
3. **Compare:** Run `check` during routine review or after an alert.
4. **Prioritize:** Examine new tasks and action, trigger, or execution-account changes; use review flags as additional context.
5. **Correlate:** Check process creation events, authentication activity, software deployment records, and change approvals where available.
6. **Document:** Preserve JSON/CSV findings and investigate unexpected changes before deliberately refreshing a baseline.

For CTI analysis, a scheduled task is one piece of evidence in an **attack sequence**; it should be correlated with temporal and tool-use patterns rather than used in isolation to attribute activity to an adversary.

## Data handling and security

- **Treat baseline and report files as potentially sensitive.** Task definitions may include internal paths, usernames, commands, arguments, URLs, or accidentally embedded secrets.
- Store baselines and exports in an access-controlled location. **Do not commit local baseline or scan files to a public repository.**
- A baseline is specific to one machine: the script rejects comparisons when the hostname differs.
- Avoid `--allow-partial` unless you understand the visibility limitations. Removed-task reporting is skipped if the baseline or current scan is incomplete.
- Registration date is task metadata and should **not** be treated as a verified creation timestamp.
- The tool cannot enumerate tasks hidden by operating-system access controls, corruption, or tampering, and does not replace endpoint detection and response telemetry.
- The script requires no network access for task enumeration. Any task command URLs shown are read from local task definitions, not accessed by the tool.

Consider adding the following entries to your repository's `.gitignore`:

```gitignore
scheduled_tasks_baseline.json
scheduled_tasks*.csv
scheduled_tasks*.json
task_changes*.csv
task_changes*.json
review_tasks*.json
__pycache__/
```

## Scope and limitations

This utility is an **inventory and change-detection aid**, not a full endpoint detection and response platform. It does not continuously monitor task registration, independently verify file signatures or hashes, establish why a task was changed, determine whether an action executed successfully, or infer adversary identity. Task modifications are detected through differences in exported task-definition XML; normal administrative or software changes may generate findings.

## References

- [MITRE ATT&CK — T1053.005: Scheduled Task](https://attack.mitre.org/techniques/T1053/005/)
- [Microsoft Learn — Task Scheduler](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-start-page)
- [Microsoft Learn — `ITaskFolder::GetTasks`](https://learn.microsoft.com/en-us/windows/win32/api/taskschd/nf-taskschd-itaskfolder-gettasks)

## Feedback and contributions

Issues, bug reports, and improvements are welcome through the [GitHub repository](https://github.com/CE47/TaskSchedule_Checker/issues). When reporting problems, remove sensitive hostnames, usernames, task arguments, and internal paths from logs or screenshots.

---

**Use only on systems you own or are authorized to assess.**
