# Kanji (D-CTF 2026 Quals - Forensics)

- **Category:** Forensics
- **Points:** 249
- **Solves:** 29
- **Author:** Dodu Andrei
- **Challenge ID:** `a263b124-1d5d-49d8-9157-36ae9c2f59cb`
- **Flag IDs Solved:** 5660, 5661, 5662, 5663, 5664, 5665, 5666, 5667, 5668, 5669 (All 10/10)
- **Status:** **Solved & Verified on CyberEDU**

---

## Executive Summary

The `Kanji` challenge presents a 29.8 GB packet capture (`small.pcap`) recorded over a 3-hour period on August 18, 2011. The capture contains approximately 28.9 million packets documenting an active IRC-based botnet (`x0n3-Satan`, a derivative of the SDBot/RxBot malware family) compromising 10 Windows XP machines (`mangled` through `mangled9` on subnet `172.16.84.0/24`) and orchestrating distributed denial-of-service (DDoS) attacks against a target system at `172.16.96.69`.

The challenge is structured as a 10-part investigation testing network forensics across multiple protocols: IRC C2 command extraction, IDENT (RFC 1413) authentication evasion, botnet host enumeration, raw socket limitation analysis on Windows XP SP2, and high-throughput ICMP/UDP flood characterization.

---

## Challenge Questions & Flags

| Flag ID | Question Summary | Submitted Value | Points |
| :--- | :--- | :--- | :--- |
| **5660** | Real username + fake usernames bypassing server identity verification | `Bob+mionrbh+ctiopej+skngobw+pnwiyg+jzeafe+dmolvw+jezircaj+mahwkq+nwltwr+alrnabq` | 22 |
| **5661** | C2 server protocol (`Format:Protocol`) | `IRC` | 12 |
| **5662** | Bot nickname pattern | `Pepe` | 13 |
| **5663** | Number of active bots | `10` | 14 |
| **5664** | Victim IP address | `172.16.96.69` | 11 |
| **5665** | UDP flood port | `161` | 13 |
| **5666** | Commands that didn't work in timeline order (`Format:.cmd1+.cmd2...`) | `.synflood+.ddos.ack+.ddos.syn` | 25 |
| **5667** | Distinct ICMP types in the flood | `256` | 18 |
| **5668** | Ping answers from victim machine | `1` | 19 |
| **5669** | Operating system name (`Format:OSName`) | `WindowsXP` | 23 |

---

## Detailed Investigation & Technical Methodology

### 1. Ingestion & Protocol Isolation

Initial analysis with `capinfos` revealed a capture size of 29,294,273,106 bytes containing 28,932,885 packets spanning 10,765 seconds. The massive volume was dominated by volumetric attack traffic.

To analyze C2 communication without processing gigabytes of flood frames repeatedly, we isolated all TCP port 6667 packets into a compact trace:
```bash
tcpdump -r small.pcap -w irc.pcap "tcp port 6667"
```
The resulting `irc.pcap` was only 658 KB, allowing instant stream reconstruction.

### 2. C2 Protocol & Bot Infrastructure (Flags 5661, 5662, 5663, 5669)

Following the TCP streams revealed 10 distinct TCP sessions established between the local subnet (`172.16.84.0/24`) and external IRC servers (`*.chatzone.net`):
- **C2 Protocol:** Internet Relay Chat (**`IRC`**).
- **Bot Nicknames:** `Pepe971541`, `Pepe858477`, `Pepe955217`, `Pepe796772`, `Pepe166191`, `Pepe470427`, `Pepe182542`, `Pepe851090`, `Pepe209833`, `Pepe428889`.
  All bots adhere strictly to the prefix pattern **`Pepe`**.
- **Active Bot Count:** 10 bots joined channel `#sysnet01` and authenticated to controller `pepe2` with password `sysnet01`:
  ```text
  :pepe2!~kvirc@gwsrv-27.labs.acme.io PRIVMSG #sysnet01 :.login sysnet01
  PRIVMSG #sysnet01 :.::[MaInFrAmE]::. Password Accettata, Welcome to x0n3-Satan.
  ```
- **Operating System Identification:**
  In response to `.sysinfo`, all bots returned their platform banner:
  ```text
  System [CPU]: 3200MHz. [RAM]: 1,048,048KB total. [Disk]: 52,420,060KB.
  [OS]: Windows XP (Service Pack 2) (5.1, Build 2600). [Hostname]: mangled (172.16.84.165). [Current User]: Bob.
  ```
  Conforming to `Format:OSName`, the OS is **`WindowsXP`**.

### 3. Identity Verification Bypass (Flag 5660)

The question asks for:
> "the bot's real reported username, and in the order they appear in the pcap by timestamp, all the fake usernames used to bypass the server's mandatory identity verification"

1. **Real Username:** Reported in `.sysinfo` as `[Current User]: Bob`.
2. **Server's Mandatory Identity Verification:**
   IRC servers execute RFC 1413 (Identification Protocol / IDENT) requests against connecting clients on TCP port 113.
   The bots embed a local identd responder. When queried by the IRC servers (`<sport> , 6667`), each bot returned a spoofed ident response:
   - `172.16.84.209` (1313665395.1177): `: USERID : UNIX : mionrbh`
   - `172.16.84.208` (1313665439.8915): `: USERID : UNIX : ctiopej`
   - `172.16.84.207` (1313665470.3210): `: USERID : UNIX : skngobw`
   - `172.16.84.206` (1313665496.8434): `: USERID : UNIX : pnwiyg`
   - `172.16.84.204` (1313665526.3157): `: USERID : UNIX : jzeafe`
   - `172.16.84.192` (1313665551.3272): `: USERID : UNIX : dmolvw`
   - `172.16.84.165` (1313665580.5901): `: USERID : UNIX : jezircaj`
   - `172.16.84.191` (1313665602.2824): `: USERID : UNIX : mahwkq`
   - `172.16.84.193` (1313665622.2601): `: USERID : UNIX : nwltwr`
   - `172.16.84.205` (1313665645.7977): `: USERID : UNIX : alrnabq`

Concatenating the real username and all 10 IDENT usernames in chronological order:
`Bob+mionrbh+ctiopej+skngobw+pnwiyg+jzeafe+dmolvw+jezircaj+mahwkq+nwltwr+alrnabq`

### 4. Flood Analysis & Attack Telemetry (Flags 5664, 5665, 5666, 5667, 5668)

To process all 28.9 million frames at line rate without python runtime bottlenecks, we developed a native C streaming parser (`fast_analyzer.c`).

#### High-Performance Analyzer Output
```text
Total packets: 28932885
Total ICMP packets: 24724598
TCP to victim: 0, from victim: 0

ICMP to victim (172.16.96.69) by type:
  Type 0 through Type 255: ~96,500 packets each
Distinct ICMP types to victim: 256

ICMP from victim (172.16.96.69) by type:
  Type 0: 1 packets
Distinct ICMP types from victim: 1

Top UDP ports to victim:
  Port 161: 2439252 packets
```

#### Correlating with IRC C2 Commands
1. **Victim IP (Flag 5664):** Controller targeted `172.16.96.69` across all attack directives.
2. **UDP Flood Port (Flag 5665):**
   ```text
   :pepe2!~kvirc@gwsrv-27.labs.acme.io PRIVMSG #sysnet01 :.udpflood 172.16.96.69 100000 1500 10 161
   ```
   Over 2.4 million UDP frames were directed to port **`161`** (SNMP).
3. **Commands That Didn't Work (Flag 5666):**
   The controller issued three TCP-based attack directives:
   - `.synflood 172.16.96.69 1 1000`
   - `.ddos.ack 172.16.96.69 1 1000`
   - `.ddos.syn 172.16.96.69 1 1000`

   Each bot immediately returned:
   ```text
   PRIVMSG #sysnet01 :[SYN]: Done with flood (0KB/sec).
   PRIVMSG #sysnet01 :[DDoS]: Done with flood (0KB/sec).
   ```
   Because Windows XP SP2 restricted raw socket creation (`AF_INET, SOCK_RAW`), the bots could not emit raw SYN or ACK frames. Total TCP packets transmitted to `172.16.96.69` was verified as exactly `0`.
   Format: `.synflood+.ddos.ack+.ddos.syn`.
4. **Distinct ICMP Types (Flag 5667):**
   The `.icmpflood` directive flooded the victim with 24.7 million ICMP packets iterating through all possible 8-bit types: **`256`** distinct types (0 through 255).
5. **Ping Answers From Victim (Flag 5668):**
   Filtering for ICMP type 0 (Echo Reply) with source IP `172.16.96.69` yielded exactly **`1`** packet.

---

## Reproducibility

The solution is fully automated via [`solve.py`](./solve.py):
```bash
python3 solve.py --submit
```
Output:
```text
======================================================================
  D-CTF 2026 Quals - Forensics: Kanji (249 pts) Solver
======================================================================

[+] Flag ID 5660: Bob+mionrbh+ctiopej+skngobw+pnwiyg+jzeafe+dmolvw+jezircaj+mahwkq+nwltwr+alrnabq
[+] Flag ID 5661: IRC
[+] Flag ID 5662: Pepe
[+] Flag ID 5663: 10
[+] Flag ID 5664: 172.16.96.69
[+] Flag ID 5665: 161
[+] Flag ID 5666: .synflood+.ddos.ack+.ddos.syn
[+] Flag ID 5667: 256
[+] Flag ID 5668: 1
[+] Flag ID 5669: WindowsXP
```
