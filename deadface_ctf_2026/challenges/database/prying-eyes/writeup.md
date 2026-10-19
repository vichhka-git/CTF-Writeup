# Prying Eyes

- **Category:** Database
- **Points:** 55

## Challenge

Aurora Health logs every time a staff member opens a patient chart. Someone was watching the VIP a little too closely. Find the user account that accessed the VIP patient's chart more times than any other account, and report their username. You'll need the VIP's MRN first from **Admitted Under Another Name**. The audit log references patients by that same MRN. Use the provided MySQL shell. Submit the username as deadface{username}. Example: deadface{jsmith}. [Access Database](https://aurora.dctf.io)

## Solution

CONFIRMED | the team queried aurora directly. `select user_id,count(*) from aurora_audit.access_log where patient_id=1007 group by user_id order by count desc` gives user 10 with 47 accesses, next highest 5 - an unmistakable outlier. aurora_audit.users resolves user_id 10 = rborden (Rebecca Borden, Health Information Clerk, HIM). Joined query confirms: rborden 47, mreyes_ehr 5, manderson12 2, ebaker7 2. NOTE both rborden and provider mreyes carry handler_ref REVENANT-7 - a cross-link that likely matters to another challenge in this series. | the team
