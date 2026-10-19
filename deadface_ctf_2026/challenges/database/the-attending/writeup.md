# The Attending

- **Category:** Database
- **Points:** 40

## Challenge

Stay on the VIP. The patient flagged `is_vip = 1` in Aurora's `patients` table had exactly one inpatient admission in November 2025. We suspect DEADFACE wants to know which physician signed off on that stay — it's the first name in the chain they leaned on. Identify the attending provider for that admission and report their system username. Use the provided MySQL shell. Submit the username as `deadface{username}`. Example: `deadface{jsmith}`.

## Solution

CONFIRMED with an alternate | the team queried aurora directly. aurora_ehr.encounters for patient 1007 has exactly ONE row: encounter 5017, Inpatient, 2025-11-14 to 2025-11-17, attending_provider_id=5, matching the challenge's "exactly one inpatient admission in November 2025". aurora_ehr.providers id 5 = Marcus Reyes, Pain Management, username **mreyes**. AMBIGUITY: the same human has a second account in aurora_audit.users as mreyes_ehr. The challenge says "report their system username" about the attending PROVIDER, so providers.username = mreyes is the primary; if rejected, try deadface{mreyes_ehr}. | the team
