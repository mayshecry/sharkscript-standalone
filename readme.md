# SharkScript

SharkScript is a high-performance, domain-specific scripting language designed for real-time network packet analysis, automation, and system orchestration. It features a custom bytecode compiler, a fast VM with a lookup-table dispatcher, and a parallel execution engine.

## Features

- **Custom Bytecode**: Compiles `.shark` source into optimized `.ligma` (LIGMA02) bytecode.
- **Parallel Execution**: Native support for multi-threaded loops using `PARALLEL LOOP`.
- **High-Precision Math**: Support for floating-point arithmetic with operator precedence (+, -, *, /).
- **Logic Engine**: Complex boolean logic evaluation (AND/OR) with packet-specific primitives.
- **Networking**: Integrated HTTP GET/POST, ISP lookup, and packet spoofing/redirection.
- **System Integration**: Asynchronous shell execution and process management (PID killing).

## Installation

Use the provided setup script to install the Go environment and the `shs` binary:

```bash
chmod +x setup.sh
./setup.sh
```

## Usage

### Compiling a script
```bash
shs --compile examples/benchmark.shark
```

### Running a script
```bash
shs --run examples/benchmark.ligma
```

## Language Syntax

### Variables and Types
Variables are stored as strings and can be referenced using `%VAR_NAME%`. The VM automatically resolves these during execution.

- `SET name value` : Simple string assignment.
- `SET result = 10 + 5 * 2` : Math assignment (supports precedence).
- `INCREMENT counter` : Adds 1 to the variable.

### Control Flow

#### Loops
Loops support both iteration counts and time durations.
- `LOOP 1000` : Runs 1000 times.
- `LOOP 5s` : Runs repeatedly for 5 seconds. Supports `ms`, `s`, `min`.
- `PARALLEL LOOP 1000000` : Distributes iterations across all available CPU cores.

#### While
- `WHILE %status% == active` : Executes as long as the condition is met.

### Logic and Conditions
The `IF` statement supports several actions: `PRINT`, `CALL`, `BLOCK`, `EXEC`, `HTTP`, `BREAK`.

- `IF %PROTO% == TCP PRINT Protocol is TCP`
- `IF MALICIOUS AND %DST_IP% == 8.8.8.8 BLOCK`
- `IF CONTAINS "payload_str" ALERT Threat Detected`

### Networking & Packet Manipulation
- `HTTP GET <url> <target_var>` : Fetches a URL.
- `HTTP POST <url> <body>` : Sends an async JSON POST.
- `SPOOF <ip>` : Changes the source IP in the packet data.
- `REDIRECT <port>` : Changes the destination port.
- `GET_ISP <ip> <var>` : Retrieves the ISP name for the given IP.

### System Actions
- `EXEC <command>` : Runs a system command asynchronously.
- `BLOCK` or `BashKILL_PID` : Terminates the process associated with the current packet.
- `SLEEP <ms>` : Pauses the current execution thread.
- `LOG <message>` : Writes a timestamped entry to `shark.log`.

### Benchmarking
- `TIME <var>` : Captures current Unix time in fractional milliseconds.
- `TIMER_START` / `TIMER_END <var>` : Utility to measure execution duration in seconds.

## Built-in Variables

When running against packet data, the following variables are pre-populated:
- `%SRC_IP%`
- `%DST_IP%`
- `%PROTO%`
- `%PROCESS%`
- `%PID%`

## Example: Benchmark

```plaintext
# Capture start time
TIME start

# Run 1 million empty iterations in parallel
PARALLEL LOOP 1000000
ENDLOOP

# Calculate delta
TIME end
SET duration = %end% - %start%

PRINT Counted to a million in %duration%ms
```