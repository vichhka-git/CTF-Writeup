# Real Pain in the Prostate  (2 of 4 series)

- **Category:** Web
- **Points:** 50

## Challenge

We are in the Health Spark application from **Doctor Appointment** at http://45.79.200.170:3000/, great work! Now let's see if we can get some access to data we shouldn't be able to see! Note: This IP address is hosting other ports for other challenges, only the website is relevant to this challenge. > NOTE: Do not perform port scanning on this host, only the address and port discovered in OSINT matter. Submit the flag as: `deadface{flag-text}` http://45.79.200.170:3000/

## Solution

Broken object-level authorisation. Logging in with the credentials leaked by the previous stage returns a signed token whose payload pins a department identifier. The patient-listing endpoint, however, takes that identifier from the REQUEST BODY rather than from the signed token, so substituting another department's identifier returns records belonging to that department. The returned data includes full personal health information, and the flag is embedded in one record's diagnosis field.
