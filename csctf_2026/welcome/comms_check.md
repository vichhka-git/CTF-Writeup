# Comms Check

**Category:** Welcome · **Points:** 100 · **Flag:** `CSCTF{comms_check_all_green_5f2c}`

## What the handout gives you

No files and no instance. The brief says the fleet runs on Discord and asks for the
recognition word the watch is broadcasting.

## Walkthrough

1. **Join the event server.** The challenge page links the Chronos Security Discord
   invite. Join it and let the onboarding bot finish, otherwise the channel list stays
   hidden behind the rules gate.

2. **Read the channels, not the messages.** The obvious places are `#news` for
   announcements and `#rules` for the rule list. Neither contains anything shaped like a
   flag, and searching the server for "recognition" or "watch" returns conversation
   about the challenge, not the word itself.

3. **Open the channel topic.** Every Discord channel has a topic string, which most
   clients only show at the top of the channel window or in the channel settings dialog.
   The topic of `#rules` reads `2026: CSCTF{comms_check_all_green_5f2c}`. That is the
   recognition word.

4. **Submit it.** Paste the `CSCTF{...}` string on its own; the `2026: ` text in front of
   it is part of the topic line, not the flag.

## Answer

`CSCTF{comms_check_all_green_5f2c}`

## Notes

The channel list is long and the topic collapses into the header on mobile. On the web
client, right-click the channel, open the channel settings, and the topic sits in the
overview panel.

This is a welcome challenge: the point is to get onto the event server, where
announcements about waves, platform issues and scoring changes appear before they reach
the challenge pages.
