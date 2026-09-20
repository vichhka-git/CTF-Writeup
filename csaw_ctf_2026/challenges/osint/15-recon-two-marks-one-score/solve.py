#!/usr/bin/env python3
"""
CSAW CTF Qualifications 2026 - OSINT
Challenge: Recon: Two Marks, One Score (ID: 15)

Solution Explanation:
1. Target Manifest / Two Coordinates:
   - First_Image.png: Architectural pediment and bell tower matching Venetian Palladian architecture (Chiesa del Santissimo Redentore / Venice, Italy).
   - Second_Image.png: Los Angeles Metro entrance sign with palm tree (Hollywood / Vine Metro Station, Los Angeles, CA).
2. The Operation:
   - The cased operation is the heist depicted in the 2003 film "The Italian Job", starring Mark Wahlberg ("Two Marks" = Mark Wahlberg, Venice Mark & LA Mark, and Saint Mark's / San Marco).
   - The crew pulls off the gold bullion heist in Venice, is betrayed by insider Steve Frazelli, and relocates to Los Angeles to reclaim the gold by dropping the armored car into the LA Metro tunnel.
3. The Insider and Sky Identifier:
   - The "potential man on the inside" is Steve Frazelli (Edward Norton).
   - On the day of the LA operation, Steve tracks the crew from high in the sky piloting a black MD Helicopters MD 500.
   - The aircraft tail registration identifier painted on the engine cowling/doghouse of the helicopter is N723KP.
"""

def get_flag():
    tail_identifier = "N723KP"
    return f"csaw{{{tail_identifier}}}"

if __name__ == "__main__":
    flag = get_flag()
    print(flag)
