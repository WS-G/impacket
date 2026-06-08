# psexec.py / RemCom — static IOCs and how to neutralise them

`examples/psexec.py` drops and runs a service binary (`RemComSvc`, from
[kavika13/RemCom](https://github.com/kavika13/RemCom)) and talks to it over named
pipes. The default build carries several **static, signatured indicators**. This
note enumerates them and documents the two evasion paths: what is configurable at
runtime today, and the recompile-and-re-embed workflow required to remove the
indicators that are baked into the compiled blob.

> Scope: this is a tradecraft reference, not a code change. The embedded
> `RemComSvc` binary cannot be altered from Python — the renamed-binary path
> below has to be built on a Windows/MSVC toolchain.

## The static indicators

| Indicator | Location | Configurable today? |
|---|---|---|
| Service name `RemComSvc` | embedded `REMCOMSVC` blob (`impacket/examples/remcomsvc.py`) + `-service-name` default `''` (random) | partly — `-service-name` renames the *installed* service, but the name inside the compiled binary is unchanged |
| Comms pipe `\RemCom_communicaton` *(sic — original RemCom typo)* | embedded `REMCOMSVC` blob | no — compiled in |
| I/O pipes `RemCom_stdout` / `RemCom_stdin` / `RemCom_stderr` | `examples/psexec.py` (client) **and** the compiled binary (server) | no — both sides must match; changing one alone breaks execution |
| Dropped binary name | `-remote-binary-name` (default randomised) | yes |

`RemComSTDOUT/STDIN/STDERR` and the service/pipe names are exactly what host- and
network-based rules key on. Renaming the service alone (`-service-name`) leaves the
pipe names and the in-binary strings intact, so it is **not** sufficient on its own.

## Path A — runtime flags (no rebuild)

Uses the stock embedded binary; reduces but does **not** remove the RemCom pipe IOCs.

```bash
psexec.py -service-name UpdateOrchestrator \
          -remote-binary-name wuauserv_helper.exe \
          DOMAIN/user@host
```

- `-service-name` — installed-service display/registry name (default `''` → random).
- `-remote-binary-name` — name of the binary written to the target share.

Good for cheap wins; leaves `\RemCom_communicaton` and `RemCom_std*` on the wire/host.

## Path B — custom service binary via `-file` (full removal)

`psexec.py -file <binary>` swaps the embedded `RemComSvc` for a binary you supply,
bypassing the blob entirely. To fully remove the IOCs you must rebuild RemCom with
renamed pipes/service **and** patch the matching client constants in `psexec.py`,
because the two sides negotiate over those exact pipe names.

### 1. Rebuild RemComSvc with renamed pipes/service (Windows + MSVC)

```
git clone https://github.com/kavika13/RemCom
```

In the RemCom source, replace every occurrence of the indicator strings with your
own (keep lengths sane, pick plausible names). At minimum:

- `RemCom_communicaton`  → e.g. `MsUpdate_ctl`
- `RemCom_stdout` / `_stdin` / `_stderr` → e.g. `MsUpdate_out` / `_in` / `_err`
- service name `RemComSvc` → e.g. `UpdateHealthSvc`

Build the **RemComSvc** project (Release, statically linked — no CRT dependency, as
the `-file` help note warns). You now have a renamed service exe.

### 2. Patch the client pipe constants to match (`examples/psexec.py`)

```python
RemComSTDOUT = "MsUpdate_out"
RemComSTDIN  = "MsUpdate_in"
RemComSTDERR = "MsUpdate_err"
```

These **must** equal the names compiled into your binary or the client will hang on
`openPipe`.

### 3. Run with your binary

```bash
psexec.py -file UpdateHealthSvc.exe \
          -service-name UpdateHealthSvc \
          -remote-binary-name uhsvc.exe \
          DOMAIN/user@host
```

### (Optional) re-embed instead of shipping a file

If you prefer the single-file `-file`-less workflow, hex-encode your rebuilt binary
and replace the `REMCOMSVC` byte literal in `impacket/examples/remcomsvc.py`:

```python
data = open("UpdateHealthSvc.exe", "rb").read()
print("".join(f"\\x{b:02x}" for b in data))   # or build the b'...' lines
```

Re-embedding bakes your renamed binary in as the new default; still requires the
client-constant patch in step 2.

## Verification

- Static (no target): `psexec.py -h` parses; `-file`/`-service-name`/`-remote-binary-name`
  accepted; client pipe constants match the rebuilt binary.
- Runtime: execute against a lab host and confirm with Sysmon (pipe-create / service-install
  events) that no `RemCom*` strings appear, plus a network capture of the pipe traffic.
  Needs a Windows target — out of scope for static review.
