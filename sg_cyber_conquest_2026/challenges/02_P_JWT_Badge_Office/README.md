# P_JWT , Badge Office

- **Challenge ID**: `1D6ENBJYEE8SMV3G7VZS7FP8EN`
- **Total Points**: 550
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Forge a warden badge (Advanced) (550 pts)

- **Task ID**: `09132BP8129JXSXAANJX9XBBHQ`
- **Checker Type**: `text`
- **Available Points**: 550

#### Credentials / Access

<a href="http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8109/" target="_blank" rel="noopener">WARDEN badge office</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

The Directorate's badge office issues signed clearance badges and publishes the key it signs them with, which is how a badge reader is supposed to work. Your badge says auditor. The clearance vault wants warden.



#### Details

Present a badge the vault accepts.

**FLAG:** What is in the vault?

The office publishes its verification key at /.well-known/jwks.json and, in the form a 1996 reader kept on disk, at /api/office/key.pem.

