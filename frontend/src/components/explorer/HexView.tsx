import { AlertTriangle } from 'lucide-react'

interface HexViewProps {
  content: string
  truncated: boolean
}

export default function HexView({ content, truncated }: HexViewProps) {
  return (
    <div className="flex flex-col gap-2">
      {truncated && (
        <div className="flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          File content truncated. Only a portion of the file is shown.
        </div>
      )}
      <pre className="overflow-auto whitespace-pre font-mono text-xs leading-5 text-foreground">
        {content}
      </pre>
    </div>
  )
}
