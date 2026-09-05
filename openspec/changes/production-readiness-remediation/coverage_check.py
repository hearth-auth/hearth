#!/usr/bin/env python3
"""Prove every finding row in the audit report has a task citing it.

Reads the report's section-4 finding tables, builds the set of section#row ids,
then reads tasks.md and extracts every citation. Prints anything uncovered.

Run from the repository root:
    python3 openspec/changes/production-readiness-remediation/coverage_check.py
Exit code 0 means every finding row has a task and every citation resolves.
"""
import re
import sys

REPORT = "reports/production-readiness-audit-2026-08-28.md"
TASKS = "openspec/changes/production-readiness-remediation/tasks.md"

# --- 1. every finding row in the report ------------------------------------
findings = {}          # "4.1#1" -> title
section = None
for line in open(REPORT, encoding="utf-8"):
    m = re.match(r"^### (4\.\d+) ", line)
    if m:
        section = m.group(1)
        continue
    if section is None:
        continue
    if line.startswith("## ") and not line.startswith("### "):
        section = None
        continue
    m = re.match(r"^\|\s*(\d+[a-z]?)\s*\|\s*(.+?)\s*\|", line)
    if m:
        findings[f"{section}#{m.group(1)}"] = m.group(2)[:70]

# --- 2. every citation in tasks.md -----------------------------------------
tasks_text = open(TASKS, encoding="utf-8").read()
cited = set(re.findall(r"§(4\.\d+)#(\d+[a-z]?)", tasks_text))
cited = {f"{s}#{n}" for s, n in cited}

# --- 3. report ---------------------------------------------------------------
uncovered = sorted(set(findings) - cited, key=lambda k: (float(k.split("#")[0][2:]), k))
phantom = sorted(cited - set(findings))

print(f"report finding rows : {len(findings)}")
print(f"distinct citations  : {len(cited)}")
print(f"tasks               : {tasks_text.count('- [ ] ')}")
print()

if uncovered:
    print(f"UNCOVERED ({len(uncovered)}) — a finding with no task:")
    for k in uncovered:
        print(f"  §{k}  {findings[k]}")
else:
    print("UNCOVERED: none. Every finding row is cited by a task.")

if phantom:
    print(f"\nPHANTOM ({len(phantom)}) — a citation with no finding row:")
    for k in phantom:
        print(f"  §{k}")
else:
    print("PHANTOM: none. Every citation resolves to a finding row.")

sys.exit(1 if uncovered or phantom else 0)
