# Silent Breaker

**Category:** forensics · **Points:** 450 · **Flag:** `CSCTF{URB1Mp5sn5pvSUJZgcIXAPrz}`

## What the handout gives you

A regional substation breaker tripped without warning. A console service (reached at the address the event platform shows you) exposes `/events`, `/query/subscriber`, `/confirm-target`, `/query/vpn-window` and `/submit`. A forensic bundle comes with it.

- `roster.json` — staff roster. Each entry has an `employee_id`, an `msisdn`, and an `ot_vpn_access` boolean.
- `events.json`, also served at `GET /events` — six flagged signalling events, all from one global title (GT).
- `iec104_capture.pcap` — a 10.5 KB IEC 60870-5-104 capture from the substation network.
- `hmi_monitoring.log` — the historian export of breaker load current for IOA `0x2550`, one reading every 10 seconds.

The report at `/submit` needs five fields: `ioa_address`, `command_qualifier`, `command_time_utc`, `telemetry_status`, `vpn_session_id`.

## Walkthrough

### 1. Find the rogue peer

The feed note states that any GT outside `GT-0000..GT-0999` is not a legitimate peer. All six events in `/events` come from `GT-3292-K57`, which is outside that range. The six MSISDNs in those events are the numbers an outside party probed.

### 2. Pick the compromised employee

The breaker sits behind the OT VPN, so the insider must hold VPN access. Match the six targeted MSISDNs against `roster.json` and keep only the entry with `ot_vpn_access: true`. Exactly one qualifies: `VLK-5961-DOB` (Ana Dobre, OT Field Engineering), MSISDN `+882-16-9265550`. That number is the target of event EVT-004, a `SendRoutingInfoForSM` lookup used to locate a subscriber.

Confirm it with `POST /confirm-target {"employee_id":"VLK-5961-DOB"}`. You get two attempts, so settle the VPN-access logic before sending. A correct answer unlocks `/query/vpn-window`.

### 3. Read the VPN session

`GET /query/vpn-window` returns the OT-VPN session opened under that employee during the incident: session `VPN-282972`. Keep the session id. The session start time is not the value the report asks for.

### 4. Find the breaker command in the capture

Filter the capture for single commands:

`tshark -r iec104_capture.pcap -Y 104asdu.typeid==45`

Type 45 is C_SC_NA_1, a single command. Two frames match, both on IOA 9552. Frame 50 carries cause of transmission 6 (activation) with the command output set ON; frame 51 is cause 7 (activation confirmation). The activation in frame 50 opened the breaker. Its wire time is 19:35:39 UTC. IOA 9552 is `0x2550`, the same point the historian logs.

### 5. Find the forged current

`hmi_monitoring.log` reports IOA `0x2550` every 10 seconds, normally near 423 A with about ±1.5 A of jitter. At 19:34:40 the value drops to 322.5 A and then repeats unchanged. From 19:35:00 the historian marks the run `QUALITY=SUSPECT`, after three identical readings. The frozen value holds 322.5 A through 19:37:30, then live readings return to about 424 A. 322.5 A sits roughly 100 A below live input, far past the 5.0 A review threshold, and still inside the 150–550 A engineering range. That is a held or replayed cache record masking the real current while the breaker was operated. The displayed frozen value is 322.5.

## Answer

Submit the completed report:

- `ioa_address`: `0x2550`
- `command_qualifier`: `ON`
- `command_time_utc`: `19:35` (the frame 50 wire time, not the VPN start)
- `telemetry_status`: `322.5`
- `vpn_session_id`: `VPN-282972`

A correct report returns the case recovery authorization, which is the flag:

`CSCTF{URB1Mp5sn5pvSUJZgcIXAPrz}`

## Notes

Each instance launch is its own case, with fresh evidence and a fresh authorization string. The employee id, session id, times and current all change per launch; the method above stays the same and the flag is whatever that case issues.

`/submit` accepts five complete reports and returns only pass or fail, with no field-by-field feedback, so derive every field from the evidence before sending. `command_time_utc` is the IEC 104 wire time of the activation, not the VPN session start, so it comes from frame 50 and not from `/query/vpn-window`. The `QUALITY=SUSPECT` marker is computed at the historian, not on the wire, so the RTU quality byte in the capture never flags the frozen reading. That is by design, and the pcap will not mark it for you.
