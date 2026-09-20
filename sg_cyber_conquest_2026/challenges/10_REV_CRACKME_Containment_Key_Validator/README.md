# REV_CRACKME , Containment Key Validator

- **Challenge ID**: `31XEW1VGGY9ZKAT3ES226Q8RCX`
- **Total Points**: 200
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Reverse the validator (Advanced) (200 pts)

- **Task ID**: `4S1THB8X718ST83X4P571EXJ3E`
- **Checker Type**: `text`
- **Available Points**: 200

#### Credentials / Access

Download: <a href="http://ec2-44-246-230-57.us-west-2.compute.amazonaws.com:8000/crackme" target="_blank" rel="noopener">crackme</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0

Linux x86-64 ELF. It will not execute on macOS or Windows, and it does not need to: a disassembler (Ghidra, Binary Ninja, radare2, objdump) reads it on any platform. If you would rather run it, Docker works: docker run --rm -it -v "$PWD:/w" -w /w --platform linux/amd64 ubuntu ./crackme

#### Description

A clearance-code validator binary, Linux x86-64. The flag is sealed under the code rather than sitting in strings, and it can be recovered by reading the binary. You do not have to run it, which matters if you are not on Linux.



#### Details

Reverse the check, recover the code, and unseal the flag.

**FLAG:** What is it?

You do not have to run anything on your own machine. <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">Open your own Linux workstation</a>, tools already installed, in your browser. There is one PER PLAYER, not one per team: take a seat from 1 to 4 below and stay on it, so two of you are not working on the same desktop.

