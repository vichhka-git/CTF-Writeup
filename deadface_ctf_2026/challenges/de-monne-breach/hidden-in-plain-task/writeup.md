# Hidden in Plain Task

- **Category:** De Monne Breach
- **Points:** 75
- **Flag:** `deadface{WindowsTelemetryCheck}`

## Challenge

An attacker registered a task to keep activity going after leaving the workstation. What is the task's exact name? Submit the name as it appears in memory. Submit the flag as `deadface{TaskName}`. Use the memory dump evidence from **Who Goes There?**

## Solution

TaskCache Tree key / TaskScheduler dynamic info: task name WindowsTelemetryCheck, LastRunTime 2026-09-27 20:23:23, action launches C:\ProgramData\WindowsCache\telemetry.ps1.
