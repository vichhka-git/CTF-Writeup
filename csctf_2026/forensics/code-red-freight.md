# Code Red Freight

**Category:** Forensics · **Points:** 270 · **Flag:** `CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}`

## What the handout gives you

The handout arrives as `code_red_freight.zip` (251,022 bytes), containing sanitized Microsoft Entra and Microsoft 365 Purview audit exports alongside phishing lure screenshots:

- `lure/email_phish.png` and `lure/devicecode_phish.png` — screenshots showing a spear-phishing email and the Microsoft device-login page (`microsoft.com/devicelogin`) used to entice rail dispatcher Patti Fernandez into authorizing an adversary device.
- `logs/AuditLogs_2026-10-29-Patti_Fernandez.csv` — 10,646-byte Microsoft Entra audit log recording directory and device management events for Patti Fernandez on 2026-10-29.
- `logs/InteractiveSignIns_2026-10-28_2026-10-29.csv` — 20,478-byte log of user interactive authentications.
- `logs/NonInteractiveSignIns_2026-10-28_2026-10-29.csv` — 255,458-byte log of background token refreshes and service authentications.
- `logs/UnifiedAuditLog_Patti.csv` — 377,730-byte Microsoft Purview Unified Audit Log (UAL) tracking Exchange Online mailbox modifications and SharePoint file access.

## Walkthrough

1. **Reconstruct the initial access vector.** The lure screenshots depict an OAuth device-code phishing attack. The adversary induced dispatcher Patti Fernandez (`PattiF@TARNOVELRAIL.OnMicrosoft.com`) to input a pairing code into Microsoft's device registration portal under the guise of provisioning field equipment.

2. **Identify the adversary device name.** In `AuditLogs_2026-10-29-Patti_Fernandez.csv`, search for device onboarding events triggered by the device registration flow:

```bash
grep "Register device" logs/AuditLogs_2026-10-29-Patti_Fernandez.csv
```

Two registration events exist: an expected corporate device (`R3M0TE-W0RK-PC`) registered on 2026-10-28 from IP `198.51.100.24`, and an anomalous device registered on 2026-10-29 at 15:05:03 UTC from external IP `203.0.113.77`. The audit event details confirm:
- Activity: `Register device`
- Device Name: `D3VC0DE-R3L4Y`
- Device ID: `95caec44-c8af-4786-976c-73bd33d9d143`
- Client IP: `203.0.113.77`

3. **Identify the exfiltration inbox rule.** After registering the device and obtaining authenticated session tokens, the adversary manipulated mailbox configuration in Exchange Online to automatically divert rail defense-consignment manifests. Search `UnifiedAuditLog_Patti.csv` for inbox rule creations:

```bash
grep "New-InboxRule" logs/UnifiedAuditLog_Patti.csv
```

The log records an event at `2026-10-29T15:28:57.0000000Z` issued from client IP `203.0.113.77:17091` and device `95caec44-c8af-4786-976c-73bd33d9d143`. The JSON parameter blob specifies:
- Rule Name: `M4N1F3ST-L3AK`
- Action: `ForwardTo: ragubarden@proton.me`
- Setting: `StopProcessingRules: True`

4. **Count adversary file downloads.** To determine the scope of stolen data, inspect the Purview audit log for file access operations originating from the adversary's IP address (`203.0.113.77`):

```bash
grep "203.0.113.77" logs/UnifiedAuditLog_Patti.csv | grep "FileDownloaded"
```

Filtering for `FileDownloaded` actions by the attacker yields four events between 15:20:24 and 15:21:36 UTC:
- `Notes.docx` (15:20:24 UTC)
- `Investor Relations Meeting Presentation.pptx` (15:20:30 UTC)
- `aerialshot.jpg` (15:20:49 UTC)
- `Local Resource Guide.docx` (15:21:36 UTC)

No other `FileDownloaded` records exist for this IP, confirming a total count of 4 downloaded files.

## Answer

Combining the rogue device name, exfiltration inbox rule, and download tally into the required format `CSCTF{<device_name>_<rule_name>_<download_count>}` gives:

`CSCTF{D3VC0DE-R3L4Y_M4N1F3ST-L3AK_4}`

## Notes

The Unified Audit Log stores command parameters as nested escaped JSON within the `AuditData` column. Grepping for the rule name directly or parsing the JSON array in row 4 (`Operation: New-InboxRule`) surfaces the `ragubarden@proton.me` forwarding action and rule name `M4N1F3ST-L3AK`.
