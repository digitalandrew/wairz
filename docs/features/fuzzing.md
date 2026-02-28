# Fuzzing

Wairz integrates AFL++ with QEMU mode for cross-architecture binary fuzzing in isolated Docker containers.

!!! warning "Experimental"
    Fuzzing support is experimental. Results may vary depending on the target binary and firmware architecture.

## Workflow

### 1. Analyze Target

Before fuzzing, analyze the binary to assess suitability:

- Fuzzing score (0-100)
- Input-handling functions
- Dangerous sinks (`strcpy`, `system`, `sprintf`, etc.)
- Binary protections
- Recommended strategy (stdin, file, or network)

Prioritize binaries with high scores.

### 2. Generate Dictionary

Extract interesting strings from the binary to create an AFL++ dictionary:

- Format specifiers
- Protocol keywords
- Magic values
- Parameter names

A good dictionary dramatically improves fuzzing effectiveness.

### 3. Generate Seed Corpus

Create minimal seed inputs based on the binary's input type:

- **stdin** — Short test strings
- **file** — Minimal file headers
- **network** — Basic protocol data

### 4. Generate Harness

Get a concrete fuzzing configuration for the binary:

- **stdin targets** — Direct fuzzing, no wrapper needed
- **file targets** — Uses `@@` argument for AFL++ file input
- **network/CGI targets** — Shell wrapper that sets environment variables
- **daemon targets** — Desocketing to redirect network I/O to stdin/stdout

### 5. Start Campaign

Launch the AFL++ campaign with the generated configuration. Only one campaign can run at a time per project.

### 6. Monitor & Triage

Check campaign statistics:

- Executions per second
- Total executions
- Corpus size
- Crash and hang counts
- Stability and coverage

When crashes are found, triage them to determine exploitability:

- **Exploitable** — Likely security vulnerability
- **Probably exploitable** — Potential security impact
- **Probably not exploitable** — Unlikely to be exploitable
- **Unknown** — Needs manual analysis

## Desocketing

For network daemon binaries, enable desocketing to intercept `socket`/`bind`/`listen`/`accept` calls and redirect network I/O to stdin/stdout. This lets AFL++ fuzz daemons that normally read from network connections.

## MCP Tools

| Tool | Description |
|------|-------------|
| `analyze_fuzzing_target` | Assess binary fuzzing suitability |
| `generate_fuzzing_dictionary` | Extract strings for AFL++ dictionary |
| `generate_seed_corpus` | Create minimal seed inputs |
| `generate_fuzzing_harness` | Get fuzzing configuration |
| `start_fuzzing_campaign` | Launch AFL++ campaign |
| `check_fuzzing_status` | Monitor campaign statistics |
| `stop_fuzzing_campaign` | Stop a running campaign |
| `triage_fuzzing_crash` | Analyze crash exploitability |
| `diagnose_fuzzing_campaign` | Troubleshoot underperforming campaigns |
