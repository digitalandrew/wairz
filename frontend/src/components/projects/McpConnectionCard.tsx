import { useState } from 'react'
import { Copy, Check, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import PromptSnippet from '@/components/ui/PromptSnippet'

interface McpConnectionCardProps {
  projectId: string
}

const SUGGESTED_PROMPTS = [
  {
    label: 'Comprehensive security assessment',
    prompt: 'Perform a comprehensive security assessment of this firmware. Start by surveying the filesystem, then check for hardcoded credentials, analyze init scripts, review binary protections, and scan for known vulnerabilities.',
  },
  {
    label: 'Analyze init scripts and boot services',
    prompt: 'Analyze the init scripts and identify all services that start at boot. Check for insecure services like telnet, FTP, or debug interfaces. Note any services running as root.',
  },
  {
    label: 'Check for hardcoded credentials and weak crypto',
    prompt: 'Check for hardcoded credentials, default passwords, and weak cryptographic material. Search /etc/shadow for empty password hashes, scan for private keys, and look for API keys or tokens in config files.',
  },
  {
    label: 'Generate SBOM and scan for known CVEs',
    prompt: 'Generate a Software Bill of Materials (SBOM) for this firmware and scan all identified components for known vulnerabilities using the NVD database.',
  },
]

export default function McpConnectionCard({ projectId }: McpConnectionCardProps) {
  const [copied, setCopied] = useState<string | null>(null)

  const containerName = 'wairz-backend-1'

  const claudeCodeCmd = `claude mcp add wairz -- docker exec -i ${containerName} uv run wairz-mcp --project-id ${projectId}`

  const claudeDesktopConfig = JSON.stringify(
    {
      mcpServers: {
        wairz: {
          command: 'docker',
          args: [
            'exec',
            '-i',
            containerName,
            'uv',
            'run',
            'wairz-mcp',
            '--project-id',
            projectId,
          ],
        },
      },
    },
    null,
    2,
  )

  const handleCopy = async (text: string, key: string) => {
    await navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(null), 2000)
  }

  const CopyButton = ({ text, id }: { text: string; id: string }) => (
    <Button
      variant="ghost"
      size="sm"
      className="h-7 px-2"
      onClick={() => handleCopy(text, id)}
    >
      {copied === id ? (
        <Check className="h-3.5 w-3.5 text-green-500" />
      ) : (
        <Copy className="h-3.5 w-3.5" />
      )}
    </Button>
  )

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <Terminal className="h-4 w-4" />
          AI Analysis via MCP
        </CardTitle>
      </CardHeader>

      <CardContent className="space-y-5 pt-0">
        <p className="text-sm text-muted-foreground">
          Connect Claude Code or Claude Desktop to Wairz's analysis tools via MCP.
          Use your own Claude subscription to analyze this firmware.
        </p>

        {/* Getting Started prompts */}
        <div className="space-y-2">
          <span className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
            Getting Started
          </span>
          <p className="text-xs text-muted-foreground">
            Copy a prompt below and paste it into your MCP client to begin analysis.
          </p>
          <div className="space-y-1.5">
            {SUGGESTED_PROMPTS.map((p) => (
              <PromptSnippet key={p.label} label={p.label} prompt={p.prompt} />
            ))}
          </div>
        </div>

        {/* Claude Code */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Claude Code</span>
            <CopyButton text={claudeCodeCmd} id="claude-code" />
          </div>
          <pre className="rounded bg-muted p-3 text-xs overflow-x-auto whitespace-pre-wrap break-all">
            {claudeCodeCmd}
          </pre>
        </div>

        {/* Claude Desktop */}
        <div className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">Claude Desktop</span>
            <CopyButton text={claudeDesktopConfig} id="claude-desktop" />
          </div>
          <pre className="rounded bg-muted p-3 text-xs overflow-x-auto">
            {claudeDesktopConfig}
          </pre>
        </div>

        <p className="text-xs text-muted-foreground">
          The MCP server runs inside the Wairz backend Docker container.
          Make sure the container is running before connecting.
        </p>
      </CardContent>
    </Card>
  )
}
