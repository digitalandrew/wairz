# Emulation

Wairz can emulate firmware using QEMU in isolated Docker containers, supporting both single-binary testing and full OS boot.

## Emulation Modes

### User Mode

Runs a single binary in a chroot environment. Fast startup, good for testing specific programs.

```
Mode: user
Binary: /usr/sbin/httpd
Arguments: -p 80
```

### System Mode

Boots the full firmware OS with a Linux kernel. Slower startup, but provides a complete environment for testing services and network behavior.

System mode automatically:

- Mounts `/proc`, `/sys`, `/dev`, `/tmp`
- Configures networking (eth0 10.0.2.15/24, gateway 10.0.2.2)
- Runs the firmware's init system

## Supported Architectures

| Architecture | QEMU Target |
|--------------|-------------|
| ARM | `qemu-arm` / `qemu-system-arm` |
| AArch64 | `qemu-aarch64` / `qemu-system-aarch64` |
| MIPS | `qemu-mips` / `qemu-system-mips` |
| MIPSel | `qemu-mipsel` / `qemu-system-mipsel` |

## Pre-Init Scripts

For system mode, use pre-init scripts to run custom setup before the firmware's init starts:

- Set `LD_PRELOAD` to inject stub libraries
- Start dependent services
- Create config files or directories the firmware expects
- Set environment variables

## Stub Profiles

Stub libraries handle hardware-specific calls that can't work in emulation:

| Profile | Description |
|---------|-------------|
| `none` | No stubs (safe for any firmware) |
| `generic` | MTD flash stubs + wireless ioctl passthrough |
| `tenda` | Generic + Tenda-specific stubs |

## Port Forwarding

Forward ports from the host to the emulated guest for testing network services:

```json
[{"host": 8080, "guest": 80}]
```

## GDB Debugging

System mode sessions include a built-in GDB stub on port 1234. Execute GDB commands for live debugging:

- Register dumps
- Breakpoints
- Backtraces
- Memory inspection

## Presets

Save working emulation configurations as named presets to reuse without re-entering all settings.

## Diagnostics

If emulation fails or services don't start:

- **Diagnose Environment** — Pre-flight check for common issues (broken symlinks, missing init, library mismatches)
- **Troubleshoot** — Firmware-aware troubleshooting guide for specific symptoms
- **Emulation Logs** — Read QEMU boot logs and serial console output
- **Crash Dumps** — Analyze core dumps from crashed binaries

## MCP Tools

| Tool | Description |
|------|-------------|
| `start_emulation` | Start a QEMU emulation session |
| `run_command_in_emulation` | Execute commands in the emulated environment |
| `stop_emulation` | Stop a running session |
| `check_emulation_status` | Check session status |
| `get_emulation_logs` | Read boot logs and serial output |
| `enumerate_emulation_services` | List listening network services |
| `diagnose_emulation_environment` | Pre-flight filesystem check |
| `troubleshoot_emulation` | Get troubleshooting advice |
| `get_crash_dump` | Analyze core dumps |
| `run_gdb_command` | Execute GDB commands |
| `save_emulation_preset` / `list_emulation_presets` | Manage presets |
| `start_emulation_from_preset` | Start from a saved preset |
