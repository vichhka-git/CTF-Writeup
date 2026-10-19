# DOOM

- **Category:** Bonus
- **Points:** 25
- **Flag:** `deadface{Lets_Play_Doom}`

## Challenge

Alright, so this isn't realy cybersecurity-related. You are playing Doom, but I mean how can you be mad when playing Doom? I have been planning on making this problem for 3 years so finally did it. Oh BTW I have been playing this game since I was like 7 so I considered making it super hard but then I decided to be nice. This is more of a fun, free bonus points challenge. Also I know this isn't actually the OG Doom. I didn't want to have license issues so I used the open-source freedoom for this! Simply download the zip file, extract it. Then open a command prompt, change into the extracted dir

## Solution

The challenge provides a Doom WAD package `DOOM.zip` containing `PWN01/PWN01/MAP01.wad`.
Parsing the lumps in `MAP01.wad` (LINEDEFS, VERTEXES, SECTORS, SIDEDEFS) reveals that near the exit room (linedefs 1150.1153 with special 52 W1 Exit Level around coordinates (2272.2336, 544.608)), there is a series of raised floor sectors (sectors 307.339, floor height 136 with FLAT19 against floor height 128 with RROCK03).
These sectors draw the flag text directly into the level floor layout:
`DEADFACE{Lets_Play_Doom}` Flag: `deadface{Lets_Play_Doom}`.
