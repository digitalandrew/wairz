import { useState } from 'react'
import { ChevronDown, ChevronRight, Copy, Check, Terminal } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'

interface McpConnectionCardProps {
  projectId: string
}

export default function McpConnectionCard({ projectId }: McpConnectionCardProps) {
  const [expanded, setExpanded] = useState(false)
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
      <CardHeader
        className="pb-3 cursor-pointer select-none"
        onClick={() => setExpanded(!expanded)}
      >
        <CardTitle className="flex items-center gap-2 text-base">
          {expanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
          <Terminal className="h-4 w-4" />
          Connect via MCP
        </CardTitle>
      </CardHeader>

      {expanded && (
        <CardContent className="space-y-4 pt-0">
          <p className="text-sm text-muted-foreground">
            Use your own Claude subscription to analyze this firmware. Connect
            Claude Desktop or Claude Code to Wairz's analysis tools via MCP.
          </p>

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
      )}
    </Card>
  )
}
