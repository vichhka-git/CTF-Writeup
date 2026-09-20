# P_WIRE , The Line Tap

- **Challenge ID**: `6Q89766XZX8EVA46FQ9WN61Y0N`
- **Total Points**: 500
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Read the sealed tunnel (Advanced) (500 pts)

- **Task ID**: `34MXM9B1RB8PHR0R94R9WD6SF0`
- **Checker Type**: `text`
- **Available Points**: 500

#### Credentials / Access

<a href="http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8110/" target="_blank" rel="noopener">WARDEN line tap, uplink 2</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

A packet capture off the Directorate's uplink, taken in the week of the audit. The uplink filter permits 53/udp unconditionally, because the resolver needs it, and that is the only rule anybody ever asked to relax.



#### Details

Recover the clearance that left the building.

**FLAG:** What was exfiltrated?

The capture is a plain pcap and opens in Wireshark or tshark. More than one thing on this link decodes cleanly; the tap log prints the checksum of the one that counts.

