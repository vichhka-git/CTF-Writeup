# Locked... or Not?

- **Category:** Mobile
- **Points:** 150

## Challenge

One of DEADFACE's junior developers has shared a new Android app that they wrote to store secure notes. We managed to get our hands on it, but when we run it, the secure note requires a password that we just can't figure out. Can you use your skills to tear the app apart and find the flag? Submit the flag as: `deadface{flag_text}`. [Download ZIP](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/mob/mob06/df-securenotes.apk.zip)(~11KB) SHA256: `b5f6e9a0a75f404103fc2d08542165015f8934e8d76433a513ca1a4705f006ca`

## Solution

CONFIRMED | the team decompiled the APK independently with jadx and read MainActivity.java. The mechanism is literal to the title: showLockedNoteDialog presents an "Authentication Required" password prompt, but its handler lambda$showLockedNoteDialog$3 unconditionally calls Toast "Access denied" - there is NO password comparison anywhere in the app, so no password can ever work (which is why the challenge says the password "we just can't guess"). The note content lives in a private, never-called method getSecureBackupText that Base64-decodes "ZGVhZGZhY2V7ZXotbW9iaWxlLXRvLXN0YXJ0fQ==" -> deadface{ez-mobile-to-start}. I then swept EVERY file in the APK (both dex, resources.arsc, res/) for any other deadface{..} literal or base64-encoded flag and found exactly one, so there is no second stage despite the 150-point value - the flag text is the author's own joke. | the team
