# CSAW CTF Quals 2026 Writeup: Keep Walking Forward

- **Category:** Misc
- **Challenge ID:** 7
- **Points:** 425
- **Solves:** 114
- **Flag:** `csaw{w4lk_b4_u_c4n_run(5p4c3)_3jfi9do9}`

---

## 1. Overview & Artifacts

The challenge provides three triage artifacts:
1. `capture.pcapng`: Packet capture of endpoint activity.
2. `vcheck.log`: SSLKEYLOGFILE containing TLS `CLIENT_RANDOM` secrets.
3. `vcheck.7z`: 7z archive containing `vcheck.exe` and a hidden `version.dll`.

The challenge description notes:
> Security pushed a GPO that disabled our access to PowerShell after some recent cases of "misuse". We still need a way to check file versions and right clicking through Properties is a chore. Luckily, our new hire wrote a utility for checking Windows binary versions and was kind enough to compress and upload it to our internal CDN for everyone to use. However, we are now receiving reports of some endpoints generating traffic to suspicious domains. The domains are, sadly, now unreachable, but we managed to get our hands on a key log file from earlier triage. Here are the artifacts we have. Can you figure out what happened and find the flag?

---

## 2. Analysis & Investigation

### Step 1: Network Traffic Decryption
Using Wireshark / `tshark` with the SSL key log (`tls.keylog_file: vcheck.log`), we decrypted all TLS conversations:
- Stream 0: `https://resources.csaw.io/tools/version-helper`
  - Client sends a `GET /tools/version-helper` with user agent `Mozilla/5.0 ... Chrome/150.0.0.0 Safari/537.36`.
  - Server returns 78,460 bytes of binary payload.
- Stream 1: `https://c2.csaw.io:4433/911ec09ffc2ef2d8923e696444c77850`
  - Client sends `POST` with form-encoded `proto=ping`.
  - Server responds with `proto=pong`.

### Step 2: DLL Sideloading & Loader Analysis
Examining `vcheck.7z` revealed `vcheck.exe` and `version.dll`:
- `vcheck.exe` is a legitimate-looking GUI application for checking PE version metadata.
- When calling `GetFileVersionInfoSizeW`, Windows loads `version.dll` from the local directory (DLL sideloading / search order hijacking).
- In `version.dll`, all other exports are forwarded to `C:\Windows\System32\version.dll`, but `GetFileVersionInfoSizeW` is hijacked.
- `vcheck.exe` passes a pointer to a struct in `r8` to `GetFileVersionInfoSizeW`.
- In `vcheck.exe`, `GetComputerNameExA(ComputerNameDnsDomain)` queries the DNS domain (`evermore.internal`).
- A key derivation function at `0x140001000` in `vcheck.exe` generates a 32-byte key from `evermore.internal`:
  ```
  key[0] = (domain[0] * 0x83) & 0xff
  key[i] = ((domain[i] * 0x83) & 0xff) ^ key[i - 1]
  ```
- `version.dll` extracts Resource 101 from `vcheck.exe`, XOR-decrypts it with an 83-byte repeating key, and hollows/injects the decrypted shellcode into `msedge.exe`.

### Step 3: Payload Decryption & Donut Loader
The injected `msedge.exe` code uses `winhttp.dll` to download `https://resources.csaw.io/tools/version-helper` and decrypts it with the 32-byte domain XOR key:
```
key = afcd6234f33e68c74df6bce04f1953f0b41b79d680478adc73f9420854fbade7
```
Once decrypted, the payload starts with `call $+0xfdc5; pop rcx`, revealing a Donut shellcode loader:
- Donut instance header at offset 5 specifies key and IV.
- The embedded module is encrypted with 16-round Chaskey in CTR mode.
- Decrypting the module with Chaskey CTR reveals a .NET assembly: `DotnetProto.exe`.

### Step 4: .NET Reverse Engineering & Flag Recovery
`DotnetProto.exe` was obfuscated using ConfuserEx 1.6.0.
By inspecting the static field byte arrays initialized in `<Module>`, we extracted the embedded PowerShell script executed via `RunspaceFactory`:
- The script sets up a fake decoy log at `C:\Windows\tracing\AiqwnI8wj.log` containing prompt-injection instructions and a decoy flag.
- The actual flag variable `${      }` is computed as:
  ```powershell
  $__ = @(0x77, 0x34, 0x6c, 0x6b) | % {[char] $_}; $__ = [string]::join('', $__); # w4lk
  $_x00 = @(0x31, 0x1a); for ($i = 0; $i -lt $_x00.length; ++$i){ $_x00[$i] = $_x00[$i] -shl 1; }; $_x00 = [string]::join('', [char[]]$_x00); # b4
  $___ = @(0x62, 0x65, 0x5e, 0x18, 0x25, 0x60, 0x24, 0x53, 0x23, 0x19) | % { $_ + 0x10 }; $___ = [string]::join('', [char[]]$___); # run(5p4c3)
  $2few8djdj9hc8d9ncen3n2oew9dn3nl8 = "n4c"; # reversed -> c4n
  $nf73jed7sdh9enn34r97vmtbuduyn = "{2}{0}{1}{3}" -f 's', 'a', 'c', 'w'; # csaw
  ${      } = $__, $_x00, "u", $2few8djdj9hc8d9ncen3n2oew9dn3nl8, $___ -join "_";
  ${      } = "$nf73jed7sdh9enn34r97vmtbuduyn{${      }";
  ${      } += "_3jfi9do9}";
  ```
Concatenating the parts gives:
`csaw{w4lk_b4_u_c4n_run(5p4c3)_3jfi9do9}`.

---

## 3. Reproduction

Run `python3 solve.py` to execute the full mathematical reconstruction pipeline.
Output:
```
csaw{w4lk_b4_u_c4n_run(5p4c3)_3jfi9do9}
```
