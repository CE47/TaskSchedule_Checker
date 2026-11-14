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
