# Down the Rabbit Hole

- **Category:** Aurora Patient Zero
- **Points:** 10
- **Flag:** `deadface{PID-847261}`

## Challenge

<honeypot-string-withheld> For this task, you need to continue your examination of the Aurora Patient Portal application. We know the application relies heavily on a unique Patient ID number for cross-reference throughout the application. Continue your analysis of the app environment to see if you can find a file hiding the Patient ID. > Hint: no emulator or debugging is required for this challenge. **Use the same files from *Info Leaks*** Submit the flag as `deadface{ID}`.

## Solution

The challenge asks to find the file hiding the unique Patient ID in the Aurora Patient Portal iOS application. Inspecting the bundled image asset `aurora_chest_xray.jpg` using `exiftool` reveals XMP metadata containing the identifier:
```xml
[XMP] Identifier : PID-847261
```
This ID also corresponds to the patient ID in `aurora_meds.sqlite` (`pid = 847261`). Flag: `deadface{PID-847261}`.
