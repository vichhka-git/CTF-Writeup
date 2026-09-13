# Spiny Trace

- **Nature:** BlueTeam
- **Type:** Classic
- **Total Tasks:** 20
- **Unlocked Tasks:** 1
- **Solved Tasks:** 0
- **Attachment Password:** `infected`
- **Download URL:** [spiny-trace.zip](https://master-platform-bucket.s3.us-east-1.amazonaws.com/challenge-groups/51804bff-1833-4aff-a40c-471e309cf973/public.zip)
- **Extracted Files Directory:** [`./files/`](./files/)

## Description & Scenario

The Intrusion Detection System flagged an unusual outbound connection from
a workstation belonging to one of the company's employees. Nothing else was
logged, no alert fired on the endpoint, and the user insists they "just
solved a captcha".



You have been handed the forensic artifacts pulled from that machine.
Reconstruct the intrusion end to end: how the user was tricked into running
the first command, what was staged next, which processes the payload hid
inside, what it stole, and where it sent the data.



**Evidence:** the artifacts are provided as a download with this challenge.


**Archive password:** `infected`



Warning: the archive contains live malware. Detonate only inside an
isolated analysis VM with networking disabled.


**- @0x4d & @m7mad**

## Tasks Overview

| # | Task Name | Status | Difficulty | Points | Solves | Solved |
|---|---|---|---|---|---|---|
| 1 | Spiny Trace 1 - Initial Access | 🔓 Unlocked | Easy | 1 | 40 | ❌ |
| 2 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 3 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 4 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 5 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 6 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 7 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 8 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 9 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 10 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 11 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 12 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 13 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 14 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 15 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 16 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 17 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 18 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 19 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |
| 20 | ??? | 🔒 Locked | - | 0 | 0 | ❌ |

## Unlocked Task Questions

### Task 1: Spiny Trace 1 - Initial Access

- **Slug:** `spiny-trace-1---initial-access`
- **Difficulty:** Easy | **Points:** 1 | **Solves:** 40

Every intrusion has a first move. In this one the attacker never exploited a
service and never sent an attachment &mdash; the user ran the code themselves,
believing they were completing a routine verification step.



Identify the MITRE ATT&amp;CK sub-technique the attacker used to gain initial
access.



**Answer format:** `T1234.004`

