# Challenge Accepted

- **Category:** De Monne Breach
- **Points:** 100
- **Flag:** `deadface{5a2342014fe7f28997ce4dcd09f6b7f8}`

## Challenge

Find Nathan's first SMB NTLMv2 authentication after the poisoned name response. What is its 16-byte `NTProofStr`? Submit the flag as `deadface{16-byte string}`. Use the PCAP from **Uninvited Guest*.

## Solution

In the packet capture, the workstation's SMB2 Session Setup carries an NTLMSSP authentication message for the compromised domain account. The NTProofStr — the first sixteen bytes of the NTLMv2 response — is the value requested. It is read directly out of the authentication blob in that frame rather than computed, and the account name in the same message matches the compromised user identified in the sibling challenges.
