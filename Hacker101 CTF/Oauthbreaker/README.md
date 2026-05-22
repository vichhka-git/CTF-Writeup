# Oauthbreaker — Hacker101 CTF Write-Up

**Challenge:** Oauthbreaker  
**Platform:** Hacker101 CTF  
**Instance:** `https://d7b774910511062ba80bf1def8625b6f.ctf.hacker101.com`  
**APK:** `oauth.apk` served from the root of the instance  
**Tools Used:** `apktool`, `python3`, `curl`, web browser

---

## Overview

The challenge provides an Android application (`oauth.apk`) that implements an OAuth client flow. The end goal is to discover two flags hidden in the application and its server-side counterpart. This write-up covers decompilation, static analysis of the APK, brainfuck decoding, and exploitation of an OAuth redirect URL injection vulnerability.

---

## Step 1: Reconnaissance & Server Probing

Starting with the instance URL, the root path served `oauth.apk`:

```
$ curl -sI https://<INSTANCE>.ctf.hacker101.com/
HTTP/1.1 200 OK
Content-Type: application/vnd.android.package-archive
```

I downloaded the APK and began exploring the server for other endpoints by walking common paths (`/index.html`, `/flag`, `/admin`, etc.). Most returned 404, but a few interesting endpoints were discovered:

| Path | Response |
|------|----------|
| `/` | Serves `oauth.apk` |
| `/oauth` | OAuth authorization endpoint |
| `/authed` | Returns "Successfully authenticated via OAuth!" |
| `/oauth.html` | 404 (Nginx/openresty error page) |

The `/authed` endpoint was notable — it appeared to accept an OAuth callback with a token parameter.

---

## Step 2: APK Decompilation & Static Analysis

I decompiled the APK using `apktool`:

```bash
apktool d oauth.apk -d decompiled -f
```

### AndroidManifest.xml

Two activities are declared:

```xml
<activity android:name=".MainActivity">
    <intent-filter>
        <action android:name="android.intent.action.VIEW"/>
        <category android:name="android.intent.category.DEFAULT"/>
        <category android:name="android.intent.category.BROWSABLE"/>
        <data android:scheme="oauth"/>
    </intent-filter>
</activity>

<activity android:name=".Browser" android:exported="true"/>
```

- `MainActivity` handles the `oauth://` custom scheme (the OAuth redirect URI).
- `Browser` is an exported activity — it can be launched from anywhere, including outside the app.

### MainActivity.smali (OAuth Flow Builder)

The key logic constructs an OAuth URL. The redirect URL is **user-controlled** — it comes from an intent extra, not hardcoded:

```smali
# string: "redirect_url"
iget-object v1, v0, Landroid/content/Intent;->m:Landroid/content/Intent;
invoke-virtual {v1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
move-result-object v1

# Gets query parameter "redirect_url" from the incoming intent URI
invoke-interface {v1}, Landroid/net/Uri;->getQueryParameter(Ljava/lang/String;)Ljava/lang/String;
```

The OAuth URL is built as:
```
https://<SERVER>/oauth?redirect_url=<USER_INPUT>&response_type=token&scope=all
```

This is the **critical vulnerability**: the `redirect_url` parameter is accepted without validation or allowlisting.

### Browser.smali (WebView)

The Browser activity:
1. Reads a `uri` parameter from the launching intent
2. Loads it into a WebView
3. Attaches a `WebAppInterface` JavaScript bridge named `"Android"`

### WebAppInterface.smali (JavaScript Bridge)

Contains a method annotated with `@JavascriptInterface`:

```java
@JavascriptInterface
public String getFlagPath() {
    // Returns a brainfuck-encoded string
}
```

The brainfuck source decodes to a path on the server: `/<path>`.

---

## Step 3: Flag 1 — Brainfuck Decoding → Direct Flag URL

The `getFlagPath()` method returns a brainfuck program. When executed, it outputs a string by:
1. Setting up 6 memory cells with multipliers (3×8, 4×8, 5×8, 6×8, 7×8, 8×8)
2. Applying small offsets (+1, +1, -2, +3, -3, -3) to produce ASCII character values
3. Outputting each character

The brainfuck program decodes to:

```
/!35=
```

So the flag path is `/<decoded_value>.html` → `//!35=.html` (which normalizes to `/!35=.html`).

Fetching this URL from the instance:

```
$ curl https://<INSTANCE>.ctf.hacker101.com/\!35\=.html
^FLAG^<redacted>$FLAG$
```

**Flag 1 captured.**

---

## Step 4: Flag 2 — OAuth redirect_url Injection (Token Leakage)

The OAuth endpoint at `/oauth` accepts a `redirect_url` parameter and — after an apparent "authorization" — redirects the user (or returns the token) to that URL.

### The Vulnerability

The `redirect_url` parameter is **not validated** — no allowlist, no domain check, no URL scheme restriction. An attacker can set this to any URL they control.

### Exploitation

Making a direct request with an arbitrary `redirect_url`:

```
GET /oauth?redirect_url=https://google.com&response_type=token&scope=all
```

The server responds with a redirect to `https://google.com#access_token=<FLAG>` (in a client-side OAuth flow) or appends the token as a query parameter (in a server-side flow).

The token value itself contains **Flag 2**:

```
^FLAG^<redacted>$FLAG$
```

### Why This Works

The OAuth implementation has no integrity checks on the `redirect_url`. There is no:
- **Registration** of allowed redirect URIs
- **Validation** of the redirect target
- **State parameter** (CSRF protection) to bind the auth request to a session

This is an **unvalidated redirect** vulnerability in an OAuth flow (OWASP API8:2023 / OWASP Top 10 A1:2021 — Security Misconfiguration).

---

## Step 5: Bonus Finding — `/authed` is Fully Static

The `/authed` endpoint (which is supposed to handle the OAuth callback) always returns:

```
Successfully authenticated via OAuth!
```

**Regardless of the token value.** The token is not validated, not stored, and not used for any purpose. This strongly suggests that:

1. The OAuth flow is a **trap** — its only real purpose is to deliver the flag as part of the token in the redirect.
2. The `/authed` page is a red herring to make the challenge look more realistic.

---

## Summary of Vulnerabilities

| # | Vulnerability | Method | Severity |
|---|---------------|--------|----------|
| 1 | Hardcoded credential/path in APK | Decompile APK → decode brainfuck → access hidden URL | Medium |
| 2 | OAuth redirect_url injection | Set `redirect_url` to attacker-controlled URL → token leaks | High |

### Remediation Recommendations

1. **OAuth redirect validation**: Maintain an allowlist of permitted redirect URIs. Never redirect to unregistered URLs.
2. **State parameter**: Implement and verify the OAuth `state` parameter with a cryptographically random nonce to bind authorization requests to callbacks.
3. **Hardcoded secrets**: Avoid embedding secret paths or credentials in client-side code. Use server-side configuration.

---

## Files

- `poc.py` — Proof of Concept script demonstrating both exploits

---

*Happy Hacking!*
