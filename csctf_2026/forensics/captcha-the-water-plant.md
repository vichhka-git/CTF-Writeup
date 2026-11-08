# CAPTCHA the Water Plant

**Category:** Forensics · **Points:** 120 · **Flag:** `CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}`

## What the handout gives you

The incident package contains KAPE triage collections from three laptops. The handout asks you to trace the user action, process execution, persistence, and browser evidence. Analyse the archives offline and compare their timelines before deciding which host contains the administrator activity.

- `ENG-LAPTOP-23.zip` contains parsed event logs, registry data, file-system records, and execution artifacts.
- `FIELD-WKS-21.zip` contains the same broad classes of KAPE output for the field workstation.
- `OPS-NB-06.zip` contains event logs, RunMRU data, scheduled-task and registry records, browser history, and Edge jump-list records.

## Walkthrough

1. Start with all three collections. ENG and FIELD contain ordinary software activity, including a legitimate AnyDesk installation on FIELD. The matching incident chain is on OPS: its parsed records tie `/validator`, a temporary AnyDesk installation, a scheduled task, and the administrator dashboard together. Compare the validator and persistence evidence across hosts when interpreting the AnyDesk traces.

2. In OPS-NB-06’s `20261028223606_RECmd_Batch_UserActivity_Output.csv`, inspect the RunMRU entry at `2026-10-21 04:30:47.7757697`. It contains a PowerShell command that downloads and executes content from `zindetify.dev.boot:8080/validator`. Correlate it with Event ID 4688, record 12091, in `20261028223252_EvtxECmd_Output.csv`. That record shows Explorer starting the PowerShell process at `2026-10-21 04:30:47.6252292`. The process event establishes execution; the RunMRU value supplies the command line.

3. Follow PowerShell Script Block logging, Event ID 4104. Record 194 contains the downloader stage. Record 196 contains the longer staging script, which fetches an AnyDesk tool and configures unattended access. The explicit `--set-password` argument is `f@k3_c@ptch@`. Use this literal, including its `@` characters, as the first flag component. Browser history adds CAPTCHA-related context. The process records establish execution.

4. Check OPS-NB-06’s `Persistence/Scheduled Tasks.csv`, then corroborate it with `20261028223437_RECmd_Batch_RegistryASEPs_Output.csv`. The task is named `\Maitenance Check 👍🙈` (the misspelling is present in the evidence), and it runs the same PowerShell validator command on a daily schedule. Its description is `_r3@l_m@lw@r3`, matching the value retrieved from the `/config` endpoint in the staging script. This is the second flag component. The task record and TaskCache registry record describe the same persistence entry.

5. Find the post-compromise panel access in `Hindsight_output.xlsx` and `20261028223326_CustomDestinations.csv`. Both record the admin dashboard URL with token `NVW-ADMIN-cl1ckf1xed`. The token prefix is `NVW-ADMIN-`; its suffix `cl1ckf1xed` supplies the final text. Put a separator underscore between that suffix and the task description when assembling the flag. The two browser artifacts corroborate the same dashboard access.

6. Read the values in order: the unattended-access password, the task description, then the dashboard token suffix. The task description already begins with an underscore. Add one more underscore between the description and the dashboard suffix. Browser history adds lure context. Windows event and task records establish the execution chain.

## Answer

Join password `f@k3_c@ptch@`, task description `_r3@l_m@lw@r3`, a separator underscore, and token suffix `cl1ckf1xed`. The result is `CSCTF{f@k3_c@ptch@_r3@l_m@lw@r3_cl1ckf1xed}`.
