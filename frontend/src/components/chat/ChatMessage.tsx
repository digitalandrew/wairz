import { User, Bot, AlertCircle } from 'lucide-react'
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
        <div className="min-w-0 pt-0.5 text-sm whitespace-pre-wrap">{message.content}</div>
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
