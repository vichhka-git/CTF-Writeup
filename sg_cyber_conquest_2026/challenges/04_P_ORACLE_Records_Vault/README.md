# P_ORACLE , Records Vault

- **Challenge ID**: `2117JFHN7T93QSHXTMN727028S`
- **Total Points**: 550
- **Depends On**: `['233VVPMDJX8MM8MHG37MFDHWV6']`
- **Dependency Met**: `False`

## Tasks

### Task 1: Forge a vault session (Advanced) (550 pts)

- **Task ID**: `7C106MGV7X8G0BHS2549PAE2KT`
- **Checker Type**: `text`
- **Available Points**: 550

#### Credentials / Access

<a href="http://ec2-52-11-248-253.us-west-2.compute.amazonaws.com:8105/" target="_blank" rel="noopener">Directorate records vault</a>

Toolkit desktops. FOUR SEATS, ONE PER PLAYER, not one shared team machine: agree who takes which. Same password on each:
  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6080/vnc.html" target="_blank" rel="noopener">seat 1</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6081/vnc.html" target="_blank" rel="noopener">seat 2</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6082/vnc.html" target="_blank" rel="noopener">seat 3</a>  <a href="http://ec2-54-244-144-91.us-west-2.compute.amazonaws.com:6083/vnc.html" target="_blank" rel="noopener">seat 4</a>
Password: 5e7fd7f0



#### Description

The records vault carries your session in an encrypted cookie. Yours says auditor. The material you want is held for warden, and the cookie is not signed.

**Expect this one to run for a while.** A full solve is thousands of requests, so a single-threaded script can sit there for twenty minutes or more. That is the beat working, not the beat broken.



#### Details

Present a session the vault serves.

**FLAG:** What is held under warden?

The vault accepts the session on the query string as /vault?s=&lt;hex&gt; as well as in the cookie, which is easier to drive from a script.

**This beat is request-heavy by nature.** A full solve is on the order of ten thousand requests, so a single-threaded script can run for twenty minutes or more against a remote host. That is the beat working, not the beat broken. Reuse one connection, and run your guesses concurrently if you want it to finish sooner.

