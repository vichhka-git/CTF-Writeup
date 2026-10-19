# Hard Kept Secrets

- **Category:** De Monne Slayer
- **Points:** 20

## Challenge

De Monne Financial has had several security incidents revolving around the latest version of their Android mobile application. Sensitive user data is being compromised left and right. De Monne is unsure how DEADFACE has access to their API. It's too early to tell if they compromised a password - let's first check if there are any hardcoded secrets in the app. Your task is to recover the internal API token from the APK. Submit the token as the flag. Example: `deadface{2GFEwQvPVIMLJmjGYHgKFWkmpuhrjEnSewMrFRyVMEQ=}` [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/d

## Solution

CONFIRMED | the team unzipped app-release.apk and decompiled with jadx: com/demonne/financial/api/ApiClient.java line 10 holds `private static final String INTERNAL_API_TOKEN = "zqJRlVwBA9Xm2lE5EPjgbj/4rOxlkYZgDtkdP7jV80rZgLFrlnOEn+VAu31YKQrR"`, passed to InternalTokenInterceptor and sent as the X-Internal-Token header. Matches the team exactly, and the challenge's own example format is a base64 blob inside deadface{}, so the token IS the flag. BONUS for later De Monne Slayer challenges: the same file exposes the API base URL http://dmf.dctf.io:8081/. | the team
