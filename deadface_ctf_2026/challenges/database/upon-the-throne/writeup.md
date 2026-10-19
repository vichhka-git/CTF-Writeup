# Upon the Throne

- **Category:** Database
- **Points:** 120
- **Flag:** `deadface{REVENANT-7}`

## Challenge

Pull the threads together. Aurora's breach was not random: an insider clerk snooped a gubernatorial candidate's chart to build kompromat, and a diversion-flagged physician was coerced into faking the Veltrexa trial that would decide a drug's approval. Both insiders were being run by the same DEADFACE handler, whose codename was recovered in a compromised-account field (`handler_ref`) on each side of the house: the audit-system users and the EHR providers. Many handler codenames appear across those two tables - around fifteen on each side, so there is no obvious one to guess - but only one appe

## Solution

Both halves of the breach store a handler codename in a `handler_ref` column: one on the audit-system users table, one on the EHR providers table, with roughly fifteen distinct codenames on each side. Intersecting the two sets isolates a single shared value. The result is then confirmed from both ends rather than trusted on its own: on the audit side it resolves to the health-information clerk identified in an earlier challenge as the one who improperly accessed a VIP chart, and on the provider side to the physician identified as the diversion-flagged prescriber. Those are precisely the two insiders the brief describes.
