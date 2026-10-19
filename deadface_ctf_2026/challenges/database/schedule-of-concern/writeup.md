# Schedule of Concern

- **Category:** Database
- **Points:** 20

## Challenge

Aurora Health's pharmacy formulary was in the DEADFACE leak. Before investigators can assess how exposed the controlled-substance supply is, they need a baseline: how many of the formulary's drugs are the most tightly regulated class — DEA Schedule II? Use the provided MySQL shell to count the Schedule II drugs in the drugs table. Submit the number as `deadface{#}`. Example: `deadface{42}`. [Access Aurora](https://aurora.dctf.io)

## Solution

CONFIRMED | the team queried aurora.dctf.io directly. Full distribution from `group by dea_schedule` on aurora_pharmacy.drugs: II=9, III=4, IV=5, N=12, V=2 (32 drugs total). Schedule II count = 9, matching the team. Showing the whole distribution rather than just the one count rules out a mis-filtered query. The challenge links hostbusters.dctf.io but the data is in aurora_pharmacy on the aurora host - the link in the description is wrong/misleading. | the team
