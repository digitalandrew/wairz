import { User, Bot, AlertCircle, FileText } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { ChatDisplayMessage } from '@/types'

interface Props {
  message: ChatDisplayMessage
}

export default function ChatMessage({ message }: Props) {
  if (message.kind === 'user') {
    return (
      <div className="flex gap-2 py-2">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary/10">
          <User className="h-3.5 w-3.5 text-primary" />
        </div>
        <div className="min-w-0 pt-0.5">
          <div className="text-sm whitespace-pre-wrap">{message.content}</div>
          {message.attachments && message.attachments.length > 0 && (
            <div className="mt-1 flex flex-wrap gap-1">
              {message.attachments.map((att) => (
                <span
                  key={att.path}
                  className="inline-flex items-center gap-1 rounded bg-muted px-1.5 py-0.5 text-xs text-muted-foreground"
                  title={att.path}
                >
                  <FileText className="h-3 w-3" />
                  {att.name}
                </span>
              ))}
            </div>
          )}
        </div>
      </div>
    )
  }

  if (message.kind === 'assistant_text') {
    return (
      <div className="flex gap-2 py-2">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-secondary">
          <Bot className="h-3.5 w-3.5 text-secondary-foreground" />
        </div>
        <div className="prose prose-sm dark:prose-invert min-w-0 max-w-none pt-0.5 text-sm [&_pre]:max-h-64 [&_pre]:overflow-auto">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{message.content}</ReactMarkdown>
        </div>
      </div>
    )
  }

  if (message.kind === 'error') {
    return (
      <div className="flex gap-2 py-2">
        <div className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-red-500/10">
          <AlertCircle className="h-3.5 w-3.5 text-red-500" />
        </div>
        <div className="min-w-0 pt-0.5 text-sm text-red-500">{message.content}</div>
      </div>
    )
  }

  // tool_call and tool_result are handled by parent grouping
  return null
}
