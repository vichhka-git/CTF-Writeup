# Diagnosis

- **Category:** De Monne Slayer
- **Points:** 100

## Challenge

One of De Monne's developers suspects there is hidden activity occurring in the app, possibly due to manifest misconfigurations. Submit the flag as `deadface{flag_text}` > Use the ZIP from **Hard Kept Secrets**

## Solution

CONFIRMED - deadface{flaG_ManIfesT3d} | the team verified in its own jadx decompilation of app-release.apk. com/demonne/financial/internal/DiagnosticActivity.java line 15 sets tvDiagOutput to a hardcoded diagnostic dump containing "diagnostic.code : deadface{flaG_ManIfesT3d}", alongside build.env=production, build.timestamp 2026-01-14 and api.endpoint http://dmf.dctf.io:8081. The activity is an internal screen shipped in a production build and reachable because it is exported in the manifest (the binary AndroidManifest lists a "Diagnostics" component; apktool is not installed here so the exported attribute was not read directly, but the flag string itself is unambiguous in the decompiled source). The flag name is the joke: it is manifested. | the team
