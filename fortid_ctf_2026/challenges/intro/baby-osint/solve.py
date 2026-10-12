#!/usr/bin/env python3
"""
Baby OSINT Solve Script
FortID CTF 2026 - intro/baby-osint
"""

import sys

def solve():
    # Question 1: Official name of the protest event in handout.jpeg
    # Taken on 2026-09-05 12:03:02 CEST at Zrinjevac park, Zagreb.
    # Civic protest by "Gospić je naš dom": "Hodaj za Liku, hodaj za Hrvatsku!"
    q1 = "hodaj_za_liku_hodaj_za_hrvatsku"

    # Question 2: Food festival in Zagreb on 2026-09-05
    # The 18th ZeGeVege festival took place on September 4-6, 2026 at Europski trg.
    q2 = "zegevege"

    # Question 3: Day of the week with largest average number of rides
    # From the Zagreb public bike system analytics (https://bajs.informacija.hr/):
    # Srijeda (Wednesday) had the highest average number of trips (17,493.5).
    q3 = "wednesday"

    # Question 4: Highest number of those bikes recorded at one location at the same time
    # On 2026-06-23 during the INmusic festival on Jarun, the temporary station
    # recorded 849 regular bikes + 60 child-seat bikes, totaling 909 bikes.
    q4 = "909"

    flag = f"FortID{{{q1}:{q2}:{q3}:{q4}}}"
    print(f"[+] Flag: {flag}")
    return flag

if __name__ == "__main__":
    solve()
