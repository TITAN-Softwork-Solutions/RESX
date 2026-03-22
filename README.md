# RESX

RESX is a fast Windows binary recon CLI for exports, PDB-backed symbols, hook checks, caller tracing, CFG inspection, and rapid IoC/TTP triage.

## Highlights

- Resolve exports, ordinals, RVAs, and PDB symbols without leaving the terminal.
- Spot hook indicators, thunk chains, EDR-style prologue tampering, and suspicious control flow quickly.
- Run `--intelli` to surface high-signal indicators like IPs, URLs, websockets, proxies, Discord token patterns, Roblox cookie formats, file paths, Minecraft session markers, network/crypto imports, and stream or execution-heavy APIs.
- Pivot into callers, CFG text views, YARA hits, PE anomalies, section metadata, strings, xrefs, and pseudo-C reconstruction from one tool.

## Build

```powershell
cargo build --release
```

## Run

```powershell
resx dump ntdll.dll NtOpenProcess
resx cfg ntdll.dll NtOpenProcess
resx dump suspicious.dll --intelli
resx dump suspicious.dll WinMain --intelli --hookchk --cfg text
resx callers .\blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub
```

## Example Output

```text
> resx dump suspicious.dll WinMain --intelli --hookchk --cfg text --strings --xrefs --quiet

suspicious.dll!WinMain  [RVA 0x00017A40, VA 0x0000000180017A40]
  mov  rcx, qword ptr [rip+0x4C12]
  call qword ptr [rip+0x2130] ; WinHttpSendRequest

Hook Indicators:
  entry starts with jump thunk
  in-memory prologue differs from disk at 5 offset(s)

Call Targets (xrefs out):
  WINHTTP.dll!WinHttpOpen
  WINHTTP.dll!WinHttpConnect
  KERNEL32.dll!CreateProcessW

String References:
  https://api.example-c2.net/gate
  wss://cdn.example-c2.net/socket
  C:\Users\Public\svchost.dat

Intelli Triage:
  [network] url (string) https://api.example-c2.net/gate
  [network] websocket (string) wss://cdn.example-c2.net/socket
  [network] host-port (string) 185.193.88.17:443
  [credential] discord-token (string) mfa.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
  [credential] roblox-cookie (string) _|WARNING:-DO-NOT-SHARE-THIS...
  [filesystem] filepath (string) C:\Users\Public\svchost.dat
  [crypto] crypto-api (import) CryptProtectData
  [execution] process-launch (import) CreateProcessW
```

```text
> resx cfg ntdll.dll NtOpenProcess --quiet

Function: ntdll!NtOpenProcess
Entry: block_00001210

block_00001210
  test r11, r11
  jne  block_00001244
  xor eax, eax
  ret
  taken -> block_00001244
  fallthrough -> exit
```

```text
> resx peinfo ntdll.dll --quiet

Image: ntdll.dll
Arch: x64
ImageBase: 0x0000000180000000
EntryPoint: 0x0009F5B0
SizeOfImage: 0x001F4000
Subsystem: 0x0003
DLL Characteristics: 0xC160
```

```text
> resx sections suspicious.dll --quiet

.text   RVA 0x00001000  VSz 0x0002A000  Raw 0x00000400  RX  entropy 6.41
.rdata  RVA 0x0002C000  VSz 0x00012000  Raw 0x0002A400  R   entropy 5.78
.data   RVA 0x0003F000  VSz 0x00004000  Raw 0x0003C400  RW  entropy 3.02
.rsrc   RVA 0x00043000  VSz 0x00009000  Raw 0x00040400  R   entropy 4.11
```

```text
> resx eat kernel32.dll --quiet

CreateFileW           ord 0x013D  RVA 0x0001A230
CreateProcessW        ord 0x0149  RVA 0x0001B940
VirtualAlloc          ord 0x05C1  RVA 0x00027B10
WriteProcessMemory    ord 0x0638  RVA 0x0005D8E0
```

```text
> resx iat suspicious.dll --quiet

KERNEL32.dll
  CreateFileW
  WriteFile
  CreateProcessW
WINHTTP.dll
  WinHttpOpen
  WinHttpConnect
  WinHttpSendRequest
```

```text
> resx syms blackbird.sys --quiet

BLACKBIRDNtAllocateVirtualMemoryHookStub  RVA 0x00001000
BlackbirdDispatchDeviceControl            RVA 0x000021F0
BlackbirdUnload                           RVA 0x00002D40
```

```text
> resx pechk suspicious.dll --quiet

[high] executable section is writable: .text
[medium] section name looks nonstandard: .xdata2
[medium] entry point is outside first executable section
```

```text
> resx callers .\blackbird.sys BLACKBIRDNtAllocateVirtualMemoryHookStub --quiet

BLACKBIRDNtAllocateVirtualMemoryHookStub  [blackbird.sys]

  blackbird.sys!BlackbirdDispatchDeviceControl +0x58
  blackbird.sys!BlackbirdWorkerThread +0x132

  2 total caller references  |  2 unique functions
```

```text
> resx locate CreateFileW --quiet

KERNEL32.dll!CreateFileW          RVA 0x0001A230
KERNELBASE.dll!CreateFileW        RVA 0x0006C910
```

```text
> resx locate-all-sym NtWriteVirtualMemory --quiet

ntdll.dll!NtWriteVirtualMemory            RVA 0x000A1230  [export]
win32u.dll!NtWriteVirtualMemory           RVA 0x0001F870  [pdb]
```

```text
> resx yara suspicious.dll rules\triage.yar --quiet

rule BeaconConfig matched suspicious.dll
rule PackedSection matched suspicious.dll
rule SuspiciousWinHTTP matched suspicious.dll
```

See `COMMANDS.md` for the command surface.
