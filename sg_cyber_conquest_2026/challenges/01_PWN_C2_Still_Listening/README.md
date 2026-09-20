# PWN_C2 , Still Listening

- **Challenge ID**: `0NG2VAWAH899B91X0R50WQMT81`
- **Total Points**: 400
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Exploit to RCE (Advanced) (400 pts)

- **Task ID**: `173RYJK37085GRJE4F7G01V7H7`
- **Checker Type**: `text`
- **Available Points**: 400

#### Credentials / Access

Service: nc ec2-44-246-230-57.us-west-2.compute.amazonaws.com 9102
Binary: <a href="http://ec2-44-246-230-57.us-west-2.compute.amazonaws.com:8000/c2" target="_blank" rel="noopener">c2</a>  (Open handout also ships <a href="http://ec2-44-246-230-57.us-west-2.compute.amazonaws.com:8000/libc.so.6" target="_blank" rel="noopener">libc.so.6</a>)

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

Something the Directorate took off P-0 is still running in the corner of the range, still listening on its port. Nobody turned it off, and it still does what it was built to do.



#### Details

Exploit the daemon, get execution, and read the flag file.

**FLAG:** What is it?

You do not have to run anything on your own machine. <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">Open your own Linux workstation</a>, tools already installed, in your browser. There is one PER PLAYER, not one per team: take a seat from 1 to 4 below and stay on it, so two of you are not working on the same desktop.

