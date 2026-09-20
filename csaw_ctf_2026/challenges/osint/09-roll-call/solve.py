#!/usr/bin/env python3
"""
Challenge 9: Roll Call - Solution Script
Reconciles the authoritative intake.db escalations against the current watchlist
via the identities table to find the two missing subjects and output the flag.
"""
import os
import sqlite3

def solve():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "roll-call", "case_file", "intake.db"),
        os.path.join(base_dir, "..", "agent_workspace", "roll-call", "case_file", "intake.db"),
        os.path.join(base_dir, "case_file", "intake.db")
    ]
    db_path = None
    for cand in candidates:
        if os.path.exists(cand):
            db_path = cand
            break

    if not db_path:
        raise FileNotFoundError("Cannot locate intake.db in candidate paths.")

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    # Get all escalated persons via identities mapping
    cur.execute("""
        SELECT DISTINCT i.person_id 
        FROM escalations e 
        JOIN identities i ON e.handle = i.handle
    """)
    escalated_persons = {row[0] for row in cur.fetchall()}

    # Get all watchlist persons via identities mapping
    cur.execute("""
        SELECT DISTINCT i.person_id 
        FROM watchlist w 
        JOIN identities i ON w.handle = i.handle
    """)
    watchlist_persons = {row[0] for row in cur.fetchall()}

    # Identify missing persons
    missing_persons = sorted(list(escalated_persons - watchlist_persons))
    
    # Retrieve primary handles for missing persons
    missing_handles = []
    for pid in missing_persons:
        cur.execute("SELECT handle FROM identities WHERE person_id = ? ORDER BY is_primary DESC", (pid,))
        handle = cur.fetchone()[0]
        missing_handles.append(handle.lower())

    # Sort handles alphabetically
    missing_handles.sort()

    flag = f"csaw{{{missing_handles[0]}_{missing_handles[1]}}}"
    print(flag)
    return flag

if __name__ == "__main__":
    solve()
