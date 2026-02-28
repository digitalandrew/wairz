# Connecting AI (MCP)

Wairz uses the [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) to give Claude access to 60+ firmware analysis tools. After starting the backend, register the MCP server with your Claude client.

## Getting Your Project ID

Each Wairz project has a unique ID. You can find it in the URL when viewing a project in the web UI, or copy it from the project settings page.

## Claude Code

```bash
claude mcp add wairz -- docker exec -i wairz-backend-1 uv run wairz-mcp --project-id <PROJECT_ID>
```

Replace `<PROJECT_ID>` with your actual project ID.

## Claude Desktop

Add to your Claude Desktop config file:

=== "Linux"

    `~/.config/Claude/claude_desktop_config.json`

=== "macOS"

    `~/Library/Application Support/Claude/claude_desktop_config.json`

```json
{
  "mcpServers": {
    "wairz": {
      "command": "docker",
      "args": [
        "exec", "-i", "wairz-backend-1",
        "uv", "run", "wairz-mcp",
        "--project-id", "<PROJECT_ID>"
      ]
    }
  }
}
```

## What Claude Can Do

Once connected, Claude has access to 60+ analysis tools and can autonomously:

- **Explore firmware** — Browse the filesystem, search for files, extract strings
- **Analyze binaries** — Decompile with Ghidra, trace dataflows, find vulnerabilities
- **Assess security** — Find credentials, crypto material, insecure configs, weak permissions
- **Generate SBOMs** — Identify software components and check for known CVEs
- **Run emulation** — Boot firmware in QEMU, test services, validate findings dynamically
- **Fuzz binaries** — Set up AFL++ campaigns with auto-generated dictionaries and corpus
- **Compare firmware** — Diff filesystems, binaries, and decompiled functions across versions
- **Record findings** — Document vulnerabilities with severity, evidence, and CWE/CVE references

## Dynamic Project Switching

The MCP server supports switching between projects without restarting. Claude can use the `switch_project` tool to change the active project during a session.

## Verifying the Connection

After configuring MCP, start a conversation with Claude and ask it to check the connection:

> "What project am I connected to?"

Claude will use the `get_project_info` tool to confirm the connection and show project details.

See the [MCP Tools Reference](../mcp-tools.md) for a complete list of available tools.
