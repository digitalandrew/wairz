import { useState } from 'react'
import { ChevronRight, Wrench, Check, X, Loader2, PlayCircle } from 'lucide-react'
import { useNavigate, useParams } from 'react-router-dom'
import { cn } from '@/lib/utils'
import type { ChatDisplayMessage } from '@/types'

interface Props {
  toolCall: Extract<ChatDisplayMessage, { kind: 'tool_call' }>
  toolResult?: Extract<ChatDisplayMessage, { kind: 'tool_result' }>
}

export default function ToolCallBlock({ toolCall, toolResult }: Props) {
  const [expanded, setExpanded] = useState(false)
  const navigate = useNavigate()
  const { projectId } = useParams<{ projectId: string }>()

  const pending = !toolResult
  const isError = toolResult?.isError

  // Show "Open in Emulation" for successful emulation tool calls
  const isEmulationTool = toolCall.tool === 'start_emulation'
  const showEmulationLink = isEmulationTool && !pending && !isError && projectId

  const borderColor = pending
    ? 'border-blue-500/40'
    : isError
      ? 'border-red-500/40'
      : 'border-green-500/40'

  return (
    <div className={cn('my-1 rounded border-l-2 bg-muted/30', borderColor)}>
      <button
        type="button"
        onClick={() => setExpanded((v) => !v)}
        className="flex w-full items-center gap-2 px-3 py-1.5 text-left text-sm hover:bg-muted/50"
      >
        <ChevronRight
          className={cn(
            'h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform',
            expanded && 'rotate-90',
          )}
        />
        <Wrench className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
        <span className="truncate font-medium">{toolCall.tool}</span>
        <span className="ml-auto shrink-0">
          {pending ? (
            <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-500" />
          ) : isError ? (
            <X className="h-3.5 w-3.5 text-red-500" />
          ) : (
            <Check className="h-3.5 w-3.5 text-green-500" />
          )}
        </span>
      </button>
      {expanded && (
        <div className="space-y-2 border-t border-border px-3 py-2">
          <div>
            <span className="text-xs font-medium text-muted-foreground">Input</span>
            <pre className="mt-0.5 max-h-48 overflow-auto rounded bg-muted p-2 text-xs">
              {JSON.stringify(toolCall.input, null, 2)}
            </pre>
          </div>
          {toolResult && (
            <div>
              <span className="text-xs font-medium text-muted-foreground">Output</span>
              <pre className="mt-0.5 max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted p-2 text-xs">
                {toolResult.output}
              </pre>
            </div>
          )}
        </div>
      )}
      {showEmulationLink && (
        <button
          onClick={() => navigate(`/projects/${projectId}/emulation`)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-primary hover:underline"
        >
          <PlayCircle className="h-3.5 w-3.5" />
          Open in Emulation
        </button>
      )}
    </div>
  )
}
