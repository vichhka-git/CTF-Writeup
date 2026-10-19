# Too Good to be True

- **Category:** Database
- **Points:** 310
- **Flag:** `deadface{VELT-0148}`

## Challenge

<honeypot-string-withheld> The post-lock edit wasn't the only fabrication in the Veltrexa trial. One subject's recorded efficacy improvement is a statistical impossibility — it sits more than three standard deviations above the study-wide mean for the primary endpoint, a telltale sign that a number was invented rather than measured. Identify that outlier subject and report their subject code. Use the provided MySQL shell. Submit the subject code as `deadface{subject_code}`. Example: `deadface{ABCD-0101}`. [Access Database](https://aurora.dctf.io)

## Solution

INDEPENDENT VERIFICATION (the team, statistics computed locally in python from a results where measure='primary_efficacy_delta' -> 60 rows. mean=2.965000, sample sd=2.830375, population sd=2.806689; 3-sigma threshold = 11.4561 (sample) / 11.3851 (pop). Exactly ONE value exceeds it: VELT-0148 value 22.00, z=+6.725 sample / +6.782 pop. Top 3 by sigma: VELT-0148 22.00 z=+6.725; VELT-0137 6.00 z=+1.072; VELT-0138 5.25 z=+0.807. Margin #1-#2 = 5.653 sigma, so the filter is unambiguous. Robust check: median 2.600, MAD 0.880, only 22.00 exceeds median+3*1.4826*MAD (robust z 14.87). Note VELT-0137 is the OTHER fabrication (the post-lock edit by mreyes from the-original-reading) and correctly does NOT clear 3 sigma here.txt.
