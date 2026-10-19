# Car Crash

- **Category:** OSINT
- **Points:** 50

## Challenge

DEADFACE has been researching companies connected to one of their latest targets. Among the files recovered was a photo of a traffic accident involving a commercial truck. We believe the truck may identify a company DEADFACE has taken an interest in. Determine which company owns the truck and when that company was founded. Submit the flag as: `deadface{MM_DD_YYYY}`. Example: `deadface{01_20_2026}` [Download PNG](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/osint/osint05/truck_crash.png)(~2.5MB) SHA256: `1aa227a57e32fb93e3cf34518902ef00e1a57b86f0929e583a017f721a0e06f8`

## Solution

CONFIRMED | Independent verification by the team. (1) I read the photo myself: "USDOT: 080806" is legible on the box truck's side; the scene (S 200th St, Westwood Square, Town Center) is set dressing, the DOT number is the pivot. (2) USDOT 80806 = J B HUNT TRANSPORT INC, Lowell AR - confirmed on FMCSA's own SMS portal (ai.fmcsa.dot.gov/SMS/Carrier/80806/Overview.aspx), not just third-party mirrors. SAFER itself 403s automated queries. (3) Founding date August 10 1961 confirmed against a PRIMARY source: the company's SEC 10-K states it was incorporated in Arkansas on that date; corroborated by the 2026 65th-anniversary release (2026-65=1961). (4) Challenge asks for MM_DD_YYYY -> 08_10_1961. Caution noted: some profiles describe a 1961 rice-hull business with trucking from 1969; the challenge asks when the COMPANY was founded and the incorporation date is the defensible reading. | the team
