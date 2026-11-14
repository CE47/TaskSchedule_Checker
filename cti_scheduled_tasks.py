#!/usr/bin/env python3
"""Windows Task Scheduler inventory and baseline-diff auditor.

Read-only. Uses Windows PowerShell 5.1 and the built-in Task Scheduler COM API.
Requires Python 3.9+ on Windows. No third-party Python packages.

Examples:
    py -3 cti_scheduled_tasks.py list
    py -3 cti_scheduled_tasks.py list --review-only --csv scheduled_tasks.csv
    py -3 cti_scheduled_tasks.py baseline
    py -3 cti_scheduled_tasks.py check
    py -3 cti_scheduled_tasks.py check --json task_changes.json

Notes:
    - Start from an elevated terminal to maximize task visibility.
    - A task missing from a partial scan is NOT treated as removed.
    - 'Review' indicators are triage hints, not a finding of maliciousness.
    - A baseline contains task action commands/arguments; protect it accordingly.
    - It cannot reveal tasks hidden from the account by OS permissions or tampering.
"""

from __future__ import annotations

import argparse
import csv
import datetime as dt
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import xml.etree.ElementTree as ET

SCHEMA_VERSION = 1
STATE_NAMES = {0: "Unknown", 1: "Disabled", 2: "Queued", 3: "Ready", 4: "Running"}

# Enumerate recursively, explicitly including TASK_ENUM_HIDDEN=1.
# Errors for inaccessible folders/tasks are preserved; they are never concealed.
POWERSHELL_COLLECTOR = r'''
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$collected = New-Object 'System.Collections.Generic.List[object]'
$warnings = New-Object 'System.Collections.Generic.List[string]'

function Format-TaskDate($value) {
    try {
        if ($null -eq $value -or $value.Year -lt 2000) { return '' }
        return $value.ToString('o')
    } catch { return '' }
}

function Read-TaskFolder($folder) {
    try {
        $entries = $folder.GetTasks(1) # TASK_ENUM_HIDDEN
        foreach ($task in $entries) {
            try {
                $collected.Add([pscustomobject]@{
                    path = [string]$task.Path
                    enabled = [bool]$task.Enabled
                    state = [int]$task.State
                    xml = [string]$task.Xml
                    last_run = Format-TaskDate $task.LastRunTime
                    next_run = Format-TaskDate $task.NextRunTime
                    last_result = [string]$task.LastTaskResult
                })
            } catch {
                $warnings.Add(('Task {0}: {1}' -f $task.Path, $_.Exception.Message))
            }
        }
    } catch {
        $warnings.Add(('Folder tasks {0}: {1}' -f $folder.Path, $_.Exception.Message))
    }

    try {
        $children = $folder.GetFolders(0)
        foreach ($child in $children) { Read-TaskFolder $child }
    } catch {
        $warnings.Add(('Folder enumeration {0}: {1}' -f $folder.Path, $_.Exception.Message))
    }
}

try {
    $service = New-Object -ComObject 'Schedule.Service'
    $service.Connect()
    Read-TaskFolder ($service.GetFolder('\'))
    $payload = [ordered]@{
        computer = [string]$env:COMPUTERNAME
        scanned_utc = (Get-Date).ToUniversalTime().ToString('o')
        tasks = @($collected.ToArray())
        warnings = @($warnings.ToArray())
    }
    ConvertTo-Json -InputObject $payload -Compress -Depth 5
} catch {
    [Console]::Error.WriteLine(('Task Scheduler collector failed: ' + $_.Exception.Message))
    exit 2
}
'''


def local_name(tag: str) -> str:
    return tag.rsplit('}', 1)[-1]


def find_child(node: ET.Element | None, name: str) -> ET.Element | None:
    if node is None:
        return None
    return next((child for child in node if local_name(child.tag) == name), None)


def nested_text(node: ET.Element | None, *names: str) -> str:
    for name in names:
        node = find_child(node, name)
    return ((node.text or '').strip() if node is not None else '')


def read_xml_task(raw: dict) -> dict:
    root = ET.fromstring(raw['xml'])
    reg = find_child(root, 'RegistrationInfo')
    actions_element = find_child(root, 'Actions')
    triggers_element = find_child(root, 'Triggers')
    settings = find_child(root, 'Settings')
    principals_element = find_child(root, 'Principals')

    actions = []
    if actions_element is not None:
        for action in actions_element:
            kind = local_name(action.tag)
            if kind == 'Exec':
                actions.append({
                    'type': kind,
                    'command': nested_text(action, 'Command'),
                    'arguments': nested_text(action, 'Arguments'),
                    'working_directory': nested_text(action, 'WorkingDirectory'),
                })
            elif kind == 'ComHandler':
                actions.append({
                    'type': kind,
                    'class_id': nested_text(action, 'ClassId'),
                    'data': nested_text(action, 'Data'),
                })
            else:
                actions.append({'type': kind, 'xml': ET.tostring(action, encoding='unicode')})

    triggers = []
    if triggers_element is not None:
        for trigger in triggers_element:
            triggers.append({
                'type': local_name(trigger.tag),
                'start_boundary': nested_text(trigger, 'StartBoundary'),
                'end_boundary': nested_text(trigger, 'EndBoundary'),
                'repetition_interval': nested_text(trigger, 'Repetition', 'Interval'),
                'enabled': nested_text(trigger, 'Enabled') or 'true',
            })

    principal = find_child(principals_element, 'Principal')
    hidden = nested_text(settings, 'Hidden').lower() == 'true'
    task = {
        'path': str(raw['path']),
        'enabled': bool(raw['enabled']),
        'hidden': hidden,
        'state': STATE_NAMES.get(int(raw.get('state', 0)), 'Unknown'),
        'author': nested_text(reg, 'Author'),
        'registration_date': nested_text(reg, 'Date'),
        'run_as': nested_text(principal, 'UserId') or nested_text(principal, 'GroupId'),
        'run_level': nested_text(principal, 'RunLevel'),
        'actions': actions,
        'triggers': triggers,
        'last_run': raw.get('last_run') or '',
        'next_run': raw.get('next_run') or '',
        'last_result': str(raw.get('last_result') or ''),
        # Fingerprint includes all task definition fields, not volatile runtime fields.
        'fingerprint': hashlib.sha256(ET.tostring(root, encoding='utf-8')).hexdigest(),
    }
    task['review_flags'] = review_indicators(task)
    return task


def review_indicators(task: dict) -> list[str]:
    flags: list[str] = []
    writable = re.compile(
        r'(?i)(%appdata%|%localappdata%|%temp%|%tmp%|\\appdata\\|'
        r'\\downloads\\|\\users\\public\\|\\programdata\\|\\temp\\)'
    )
    interpreters = {
        'powershell.exe', 'pwsh.exe', 'cmd.exe', 'wscript.exe', 'cscript.exe',
        'mshta.exe', 'rundll32.exe', 'regsvr32.exe', 'certutil.exe', 'bitsadmin.exe',
        'wmic.exe', 'python.exe', 'pythonw.exe', 'msiexec.exe',
    }
    indicators = re.compile(
        r'(?i)(-encodedcommand\b|-enc\b|\bfrombase64string\b|\bdownloadstring\b|'
        r'\binvoke-expression\b|\biex\s*\(|\bhttp[s]?://|\bwindowstyle\s+hidden\b)'
    )
    for action in task['actions']:
        if action['type'] != 'Exec':
            continue
        command = action.get('command', '')
        combined = (command + ' ' + action.get('arguments', '') + ' ' +
                    action.get('working_directory', ''))
        normalized = command.strip().strip('"').replace('/', '\\').lower()
        exe_name = normalized.rsplit('\\', 1)[-1]
        if writable.search(combined):
            flags.append('Action references a commonly user-writable directory')
        if exe_name in interpreters:
            flags.append('Interpreter or dual-use utility in task action')
        if indicators.search(combined):
            flags.append('Action arguments contain a command/download review indicator')
    if task['hidden']:
        flags.append('Task has Hidden=true (often legitimate)')
    return list(dict.fromkeys(flags))


def scan_tasks() -> tuple[dict, dict[str, dict]]:
    if os.name != 'nt':
        raise RuntimeError('This script must be run on Windows.')
    # PowerShell -EncodedCommand takes UTF-16LE base64. The collector is embedded,
    # never assembled from user input, and makes no configuration changes.
    import base64
    encoded = base64.b64encode(POWERSHELL_COLLECTOR.encode('utf-16-le')).decode('ascii')
    result = subprocess.run(
        ['powershell.exe', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
        capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=180,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError((result.stderr or result.stdout).strip() or
                           f'PowerShell exited with code {result.returncode}')
    try:
        payload = json.loads(result.stdout.lstrip('\ufeff').strip())
    except json.JSONDecodeError as exc:
        raise RuntimeError(f'Could not parse Task Scheduler output: {exc}; '
                           f'PowerShell output: {result.stdout[:400]!r}') from exc

    tasks: dict[str, dict] = {}
    warnings = list(payload.get('warnings') or [])
    for raw in payload.get('tasks') or []:
        try:
            task = read_xml_task(raw)
            tasks[task['path'].lower()] = task
        except (KeyError, ValueError, ET.ParseError) as exc:
            warnings.append(f"Failed to parse {raw.get('path', '?')}: {exc}")
    payload['warnings'] = warnings
    return payload, tasks


def changed_fields(previous: dict, current: dict) -> list[str]:
    """Report security-relevant differences, not volatile last/next-run fields."""
    checked = ['enabled', 'hidden', 'author', 'registration_date', 'run_as',
               'run_level', 'actions', 'triggers']
    fields = [field for field in checked if previous.get(field) != current.get(field)]
    if not fields:
        fields.append('other task-definition XML fields')
    return fields


def describe_action(action: dict) -> str:
    if action['type'] == 'Exec':
        return ' '.join(part for part in [action.get('command', ''),
                                          action.get('arguments', '')] if part)
    if action['type'] == 'ComHandler':
        return f"COM handler: {action.get('class_id', '')}"
    return action['type']


def describe_trigger(trigger: dict) -> str:
    parts = [trigger['type']]
    if trigger.get('start_boundary'):
        parts.append('starts ' + trigger['start_boundary'])
    if trigger.get('repetition_interval'):
        parts.append('repeat ' + trigger['repetition_interval'])
    if trigger.get('enabled', 'true').lower() == 'false':
        parts.append('disabled')
    return ' | '.join(parts)


def format_task(task: dict, label: str = '') -> str:
    header = f"[{label}] {task['path']}" if label else task['path']
    lines = [header,
             f"  State: {task['state']} | Enabled: {task['enabled']} | Hidden: {task['hidden']}",
             f"  Author: {task['author'] or '(not specified)'} | Run as: {task['run_as'] or '(not specified)'} | Run level: {task['run_level'] or '(default)'}",
             f"  Registered (metadata): {task['registration_date'] or '(not provided)'}",
             f"  Last run: {task['last_run'] or '-'} | Next run: {task['next_run'] or '-'} | Result: {task['last_result'] or '-'}"]
    for i, action in enumerate(task['actions'], start=1):
        lines.append(f"  Action {i}: {describe_action(action) or '(none)'}")
        if action.get('working_directory'):
            lines.append(f"            Working dir: {action['working_directory']}")
    if not task['actions']:
        lines.append('  Actions: (none)')
    for i, trigger in enumerate(task['triggers'], start=1):
        lines.append(f"  Trigger {i}: {describe_trigger(trigger)}")
    if not task['triggers']:
        lines.append('  Triggers: (none)')
    if task['review_flags']:
        lines.append('  Review indicators: ' + '; '.join(task['review_flags']))
    return '\n'.join(lines)


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def safe_csv_text(value: object) -> str:
    """Prevent Excel/LibreOffice CSV formula execution from adversarial task names/args."""
    text = str(value)
    if text.lstrip().startswith(('=', '+', '-', '@')):
        return "'" + text
    return text


def export_csv(path: Path, selected: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    cols = ['path', 'state', 'enabled', 'hidden', 'author', 'registration_date',
            'run_as', 'run_level', 'actions', 'triggers', 'last_run', 'next_run',
            'last_result', 'review_flags', 'fingerprint']
    with path.open('w', encoding='utf-8-sig', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=cols)
        writer.writeheader()
        for task in selected:
            row = {col: task[col] for col in cols}
            row['actions'] = ' | '.join(describe_action(a) for a in task['actions'])
            row['triggers'] = ' | '.join(describe_trigger(t) for t in task['triggers'])
            row['review_flags'] = ' | '.join(task['review_flags'])
            writer.writerow({key: safe_csv_text(value) for key, value in row.items()})


def main() -> int:
    parser = argparse.ArgumentParser(
        description='Read-only Windows Scheduled Tasks inventory and CTI baseline comparison.')
    parser.add_argument('command', nargs='?', choices=['list', 'baseline', 'check'],
                        default='list', help='List tasks, save trusted baseline, or compare.')
    parser.add_argument('--baseline', type=Path, default=Path('scheduled_tasks_baseline.json'),
                        help='Baseline file path (default: ./scheduled_tasks_baseline.json).')
    parser.add_argument('--csv', type=Path, help='Export displayed tasks as CSV.')
    parser.add_argument('--json', type=Path, help='Export scan/results as JSON.')
    parser.add_argument('--review-only', action='store_true',
                        help='For list: show only tasks with review indicators.')
    parser.add_argument('--match', type=str,
                        help='For list: case-insensitive text to find in paths/actions.')
    parser.add_argument('--allow-partial', action='store_true',
                        help='Allow saving a baseline despite enumeration warnings (not advised).')
    parser.add_argument('--force', action='store_true',
                        help='Overwrite an existing baseline (only when deliberately refreshing).')
    args = parser.parse_args()

    if args.command == 'baseline' and args.baseline.exists() and not args.force:
        print(f'ERROR: Baseline already exists: {args.baseline}\n'
              'Refusing to overwrite it. Use --force only after investigation.', file=sys.stderr)
        return 2

    try:
        payload, inventory = scan_tasks()
    except (RuntimeError, subprocess.TimeoutExpired, OSError) as exc:
        print(f'ERROR: {exc}', file=sys.stderr)
        return 2

    tasks = sorted(inventory.values(), key=lambda task: task['path'].lower())
    warnings = payload['warnings']
    print(f"Host: {payload.get('computer', '?')} | Scanned: {payload.get('scanned_utc', '?')} | Tasks visible: {len(tasks)}")
    if warnings:
        print(f'WARNING: {len(warnings)} enumeration/parse error(s); inventory may be incomplete.',
              file=sys.stderr)
        for msg in warnings[:25]:
            print(f'  - {msg}', file=sys.stderr)
        if len(warnings) > 25:
            print(f'  ... {len(warnings) - 25} additional warnings', file=sys.stderr)

    if args.command == 'baseline':
        if warnings and not args.allow_partial:
            print('Baseline NOT saved because the inventory is incomplete. Run as Administrator '
                  'and resolve warnings, or explicitly use --allow-partial.', file=sys.stderr)
            return 2
        snapshot = {
            'schema': SCHEMA_VERSION,
            'computer': payload.get('computer', ''),
            'created_utc': payload.get('scanned_utc', ''),
            'partial': bool(warnings),
            'tasks': {task['path'].lower(): task for task in tasks},
        }
        write_json(args.baseline, snapshot)
        print(f'Baseline saved: {args.baseline} ({len(tasks)} tasks).')
        print('Protect this file: task arguments can contain sensitive information.')
        return 0

    if args.command == 'check':
        if not args.baseline.is_file():
            print('ERROR: No baseline. First create one from a trusted system state using '
                  f'"python {Path(__file__).name} baseline".', file=sys.stderr)
            return 2
        try:
            baseline = json.loads(args.baseline.read_text(encoding='utf-8'))
            if baseline.get('schema') != SCHEMA_VERSION or not isinstance(baseline['tasks'], dict):
                raise ValueError('unrecognized baseline format')
        except (OSError, ValueError, KeyError) as exc:
            print(f'ERROR: Could not read baseline: {exc}', file=sys.stderr)
            return 2
        saved_host = str(baseline.get('computer', '')).casefold()
        current_host = str(payload.get('computer', '')).casefold()
        if saved_host != current_host:
            print(f'ERROR: Baseline is for {saved_host!r}, current host is {current_host!r}. '
                  'Do not compare baselines across machines.', file=sys.stderr)
            return 2

        old = baseline['tasks']
        new_keys = sorted(inventory.keys() - old.keys())
        shared_keys = inventory.keys() & old.keys()
        changed_keys = sorted(key for key in shared_keys if
                              inventory[key]['fingerprint'] != old[key].get('fingerprint'))
        # Missing tasks might simply be permission/visibility problems.
        removed_keys = sorted(old.keys() - inventory.keys()) if not warnings and not baseline.get('partial') else []
        if warnings or baseline.get('partial'):
            print('REMOVED task analysis skipped: current or baseline scan is incomplete.')
        print(f'Baseline: {args.baseline}\n'
              f'NEW: {len(new_keys)} | MODIFIED: {len(changed_keys)} | '
              f'REMOVED: {len(removed_keys)}')
        for label, keys in [('NEW', new_keys), ('MODIFIED', changed_keys)]:
            for key in keys:
                print('\n' + format_task(inventory[key], label))
                if label == 'MODIFIED':
                    delta = changed_fields(old[key], inventory[key])
                    print('  Fields changed: ' + ', '.join(delta))
                    if 'actions' in delta:
                        old_actions = '; '.join(describe_action(a) for a in old[key].get('actions', []))
                        print('  Previous actions: ' + (old_actions or '(none)'))
        for key in removed_keys:
            print(f'\n[REMOVED] {old[key].get("path", key)}')

        report = {
            'host': payload.get('computer', ''), 'scanned_utc': payload.get('scanned_utc', ''),
            'baseline': str(args.baseline), 'warnings': warnings,
            'new': [inventory[k] for k in new_keys],
            'modified': [{**inventory[k],
                          'fields_changed': changed_fields(old[k], inventory[k]),
                          'previous_actions': old[k].get('actions', [])}
                         for k in changed_keys],
            'removed': [old[k] for k in removed_keys],
            'removed_comparison_skipped': bool(warnings or baseline.get('partial')),
        }
        if args.json:
            write_json(args.json, report)
            print(f'JSON report: {args.json}')
        if args.csv:
            export_csv(args.csv, report['new'] + report['modified'])
            print(f'CSV report: {args.csv}')
        # 10 signals a meaningful diff for automation; 2 signals incomplete/error.
        if warnings:
            return 2
        return 10 if new_keys or changed_keys or removed_keys else 0

    selected = tasks
    if args.review_only:
        selected = [task for task in selected if task['review_flags']]
    if args.match:
        needle = args.match.casefold()
        selected = [task for task in selected if needle in task['path'].casefold()
                    or any(needle in describe_action(a).casefold() for a in task['actions'])]
    print(f'Displaying {len(selected)} of {len(tasks)} tasks. '
          f"Tasks with review indicators: {sum(bool(t['review_flags']) for t in tasks)}")
    for task in selected:
        print('\n' + format_task(task))
    if args.csv:
        export_csv(args.csv, selected)
        print(f'\nCSV inventory: {args.csv}')
    if args.json:
        write_json(args.json, {
            'host': payload.get('computer', ''),
            'scanned_utc': payload.get('scanned_utc', ''),
            'warnings': warnings,
            'tasks': selected,
        })
        print(f'JSON inventory: {args.json}')
    return 2 if warnings else 0


if __name__ == '__main__':
    sys.exit(main())
