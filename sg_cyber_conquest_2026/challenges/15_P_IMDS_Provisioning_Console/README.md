# P_IMDS , Provisioning Console

- **Challenge ID**: `540M7S7KQH8X1TZ7ZNKYDWPM9J`
- **Total Points**: 650
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Reach the provisioning bus (Advanced+) (650 pts)

- **Task ID**: `11FW6Z4BZG803VQ48HYKT8V36Z`
- **Checker Type**: `text`
- **Available Points**: 650

#### Credentials / Access

<a href="http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8108/" target="_blank" rel="noopener">Directorate provisioning console</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

A Solaris provisioning console in the Directorate's machine room. Staff use it to check whether a page is reachable from a node without logging in to the node. The node collects its own credentials at boot from a bus that answers anything arriving from the node.



#### Details

Get the clearance the bus holds for this node.

**FLAG:** What does the clearance endpoint release?

The console is the only way in. Nothing here reaches any real cloud account, and the credentials the bus issues mean nothing outside this challenge.

