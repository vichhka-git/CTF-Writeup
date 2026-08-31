# save the water - Forensics Writeup

## Challenge Overview
- **Category:** Forensics (400 points)
- **Attachment:** `public.7z` containing `public.pcap`
- **Remote Service:** 11-question incident response questionnaire
- **Flag:** `COMPFEST18{b0r05_41r_vv0y_j4n64n_p3cu7_p3cu7_41_mu1u_dfmabfbfdadf}`

## Step-by-Step Question Solutions

1. **Q1: Victim IP Address**
   - Inspection of IPv4 conversations revealed only two hosts: `192.168.100.10` and `192.168.100.20`.
   - `192.168.100.10` initiated HTTP GET requests and was attacked.
   - **Answer:** `192.168.100.10`

2. **Q2: Versioning Artifact**
   - The HTTP GET request User-Agent contains `WindowsPowerShell/5.1.26100.8521`.
   - **Answer:** `5.1.26100.8521`

3. **Q3: Authentication Magic Bytes**
   - TCP Stream 0 on port 4444 contains the authentication handshake payload `deadbeef_AUTH_SUCCESS`.
   - The first 4 bytes formatted as `xx-xx-xx-xx` are:
   - **Answer:** `de-ad-be-ef`

4. **Q4: Multimedia Datagram Stream SSRC**
   - UDP traffic on port 1234 carries an RTP media stream with SSRC `0x82e7d63a` = `2196231738`.
   - **Answer:** `2196231738`

5. **Q5: Secret String Hidden Without Data Payload**
   - Analysis of ICMP Echo Requests with ID `9999` revealed 281 packets with inter-arrival time deltas of ~1.0s ('0') and ~2.0s ('1').
   - Decoding the binary timing covert channel yields `d0nt_ruN_th3_m4lw4r3_y4hh_82117caa` (34 characters).
   - **Answer:** `d0nt_ruN_th3_m4lw4r3_y4hh_82117caa`

6. **Q6: Reconstructed Massive Payload Fragmented Across Traffic MD5**
   - Concatenating the `EXFIL` payloads across 32,221 ICMP Echo Requests (ID `1337`) reassembles a 45,109,394-byte Windows Minidump file (`MDMP`).
   - MD5 hash of this reassembled dump: `c61e123e24a6025bc1aac86391385070`.
   - **Answer:** `c61e123e24a6025bc1aac86391385070`

7. **Q7: AES Key and IV in Memory**
   - Searching the extracted memory dump reveals the running `cctv_service.py` script.
   - Decryption verification of `video.enc` identifies AES-CBC Key `bd7bf788d62bdec9c219316da4487314` and IV `y0u_g0t_tr4pp3d!`.
   - **Answer:** `bd7bf788d62bdec9c219316da4487314_y0u_g0t_tr4pp3d!`

8. **Q8: Multi-digit Authorization Code Revealed in Evidence**
   - Decrypting `video.enc` yields `video.zip` -> `video.mp4`.
   - Examining the video frames reveals handwritten digits on paper: `16031115`.
   - **Answer:** `16031115`

9. **Q9: SHA256 Hash of Malware**
   - Unzipping `private.676767` with password `d0nt_ruN_th3_m4lw4r3_y4hh_82117caa512de1cc679e2acb37092e10a6111c22` gives `fastAI.zip`.
   - Unzipping `fastAI.zip` with authorization password `16031115` extracts `fastloader.exe`.
   - SHA256 of `fastloader.exe`: `be69c8c00b73aadbb26ca44707ec1d489f891d2e848dd7e834b8f881bcdeb33d`.
   - **Answer:** `be69c8c00b73aadbb26ca44707ec1d489f891d2e848dd7e834b8f881bcdeb33d`

10. **Q10: Hexadecimal Offset and Size of Data Block**
    - Analyzing `fastloader.exe` shows an NSIS overlay block starting at offset `0x00009600` of size `0x046ecd9d`.
    - **Answer:** `00009600_046ecd9d`

11. **Q11: Original Developer of Privilege Escalation Utility**
    - Inside `$PLUGINSDIR/app-64.7z`, the binary `resources/elevate.exe` contains Company / Copyright metadata for Johannes Passing.
    - **Answer:** `Johannes_Passing`
