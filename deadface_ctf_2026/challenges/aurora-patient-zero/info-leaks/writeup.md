# Info Leaks

- **Category:** Aurora Patient Zero
- **Points:** 25
- **Flag:** `deadface{mara-voss-1988-04-17}`

## Challenge

<honeypot-string-withheld> Aurora Health has been dealing with a wave of highly targeted phishing attacks against its patients. The messages are convincing, contain accurate patient information, and are resulting in an alarming number of successful compromises. Investigators have identified one common link among the victims: every affected patient recently installed Aurora Health's new Patient Portal iOS application. Security analysts suspect the app may be exposing sensitive information that DEADFACE is using to craft its phishing campaigns. We have been given a copy of the application for an

## Solution

The challenge provides an iOS application package `AuroraPatientPortal.ipa.zip`. Analysis of the app bundle reveals an embedded configuration property in `Info.plist` named `AuroraPatientBootstrap`. The base64-encoded string decodes to JSON identifying the last patient who used the application:
```json
{"patientName":"Mara Voss","dateOfBirth":"1988-04-17","clinic":"Westlake"}
```
Formatting as `deadface{firstname-lastname-YYYY-MM-DD}` yields `deadface{mara-voss-1988-04-17}`.
