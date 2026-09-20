# REV_WHISPER , WHISPER Beacon

- **Challenge ID**: `7ZXDR2YJNF8P0VFXG0D0AP7VNA`
- **Total Points**: 250
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Speak the protocol (Advanced+) (250 pts)

- **Task ID**: `4C0X0M576D98YAGEGWAN3M1VQH`
- **Checker Type**: `text`
- **Available Points**: 250

#### Credentials / Access

Service: nc ec2-18-236-161-153.us-west-2.compute.amazonaws.com 9002
Binary: <a href="http://ec2-44-246-230-57.us-west-2.compute.amazonaws.com:8000/whisper" target="_blank" rel="noopener">whisper</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

A TCP beacon speaking a private WHSP binary protocol. The token is never in the binary; it is sealed on the wire, so you must complete a live session.



#### Details

Reverse the wire format, write a client, and capture the token live.

**FLAG:** What is it?

You do not have to run anything on your own machine. <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">Open your own Linux workstation</a>, tools already installed, in your browser. There is one PER PLAYER, not one per team: take a seat from 1 to 4 below and stay on it, so two of you are not working on the same desktop.

