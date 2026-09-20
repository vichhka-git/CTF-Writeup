#!/usr/bin/env python3
"""
CSAW CTF Qualifications 2026
Challenge: Like a Sword Through the Heart (ID: 3)
Category: OSINT
Author: Garlic

Solution script and verification.
"""

def solve():
    # Riddle breakdown:
    # "Comradery and brotherhood, fighting side by side."
    # -> Cleitus the Black and Alexander the Great. Cleitus saved Alexander's life
    #    at the Battle of the Granicus, fighting side by side throughout the campaign.
    #
    # "All put to an end over a clouded fight."
    # -> In 328 BC at Maracanda, an alcohol-clouded violent argument erupted between
    #    Alexander and Cleitus during a banquet.
    #
    # "Two men fought, one left distraught."
    # -> Alexander killed Cleitus with a javelin/spear piercing his chest/heart.
    #    Alexander immediately was overcome with grief, became suicidal, wept for days,
    #    utterly distraught.
    #
    # "Find the name of the other man."
    # -> Cleitus the Black
    #
    # Flag format: csaw{full_name_or_title_of_the_man} (not case sensitive)
    name = "cleitus_the_black"
    flag = f"csaw{{{name}}}"
    return flag

if __name__ == "__main__":
    flag = solve()
    print(flag)
