# UART Console

Wairz supports connecting to physical devices via UART serial console through a host-side bridge.

## Architecture

USB serial adapters can't easily pass through to Docker containers, so UART access uses a two-part architecture:

```
Physical Device <--UART--> USB Adapter <--USB--> Host Machine
                                                      |
                                            wairz-uart-bridge.py
                                              (TCP port 9999)
                                                      |
                                              Docker Backend
                                            (uart_service.py)
```

## Setting Up the Bridge

### 1. Install pyserial

On the host machine (not inside Docker):

```bash
pip install pyserial
```

### 2. Start the Bridge

```bash
python scripts/wairz-uart-bridge.py --port /dev/ttyUSB0 --baud 115200
```

Common serial devices:

| OS | Device Path |
|----|-------------|
| Linux | `/dev/ttyUSB0`, `/dev/ttyACM0` |
| macOS | `/dev/tty.usbserial-*` |

Common baud rates: 115200 (most common), 9600, 57600, 38400.

### 3. Allow Docker Traffic

On Linux, you may need to allow Docker bridge traffic to reach the bridge:

```bash
sudo iptables -A INPUT -i docker0 -p tcp --dport 9999 -j ACCEPT
```

## Using the Console

Once the bridge is running, connect through the MCP tools or web UI:

1. **Connect** — Specify device path, baud rate, data bits, parity, and stop bits
2. **Send commands** — Execute shell commands and wait for the prompt
3. **Read output** — Capture boot logs, async output, or continuous data
4. **Send break** — Interrupt U-Boot autoboot or trigger debug consoles
5. **Disconnect** — Close the serial connection

## U-Boot Interaction

To interact with U-Boot:

1. Connect before powering on the device
2. Send a serial BREAK during the autoboot countdown
3. Use `uart_send_command` with `prompt='=> '` for U-Boot commands

## MCP Tools

| Tool | Description |
|------|-------------|
| `uart_connect` | Connect to serial device |
| `uart_send_command` | Send command and wait for prompt |
| `uart_read` | Read from receive buffer |
| `uart_send_break` | Send serial BREAK signal |
| `uart_send_raw` | Send raw bytes |
| `uart_disconnect` | Close connection |
| `uart_status` | Check connection status |
| `uart_get_transcript` | Get session transcript |
