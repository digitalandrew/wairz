import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { MessageSquare, X, Send, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useChatStore } from '@/stores/chatStore'
import { useWebSocket } from '@/hooks/useWebSocket'
import { createConversation } from '@/api/chat'
import ChatMessage from './ChatMessage'
import ToolCallBlock from './ToolCallBlock'
import type { ChatDisplayMessage } from '@/types'

interface ChatPanelProps {
  isOpen: boolean
  onToggle: () => void
}

export default function ChatPanel({ isOpen, onToggle }: ChatPanelProps) {
  const { id: projectId } = useParams<{ id: string }>()
  const conversationId = useChatStore((s) => s.conversationId)
  const messages = useChatStore((s) => s.messages)
  const connectionStatus = useChatStore((s) => s.connectionStatus)
  const isStreaming = useChatStore((s) => s.isStreaming)
  const currentTextAccumulator = useChatStore((s) => s.currentTextAccumulator)
  const setConversationId = useChatStore((s) => s.setConversationId)

  const { sendMessage } = useWebSocket(projectId!, conversationId)

  const [input, setInput] = useState('')
  const [initializing, setInitializing] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  // Create conversation on first open if needed
  useEffect(() => {
    if (!isOpen || conversationId || initializing || !projectId) return
    setInitializing(true)
    createConversation(projectId, 'New chat')
      .then((c) => setConversationId(c.id))
      .catch(() => useChatStore.getState().addError('Failed to create conversation'))
      .finally(() => setInitializing(false))
  }, [isOpen, conversationId, projectId, initializing, setConversationId])

  // Auto-scroll logic
  useEffect(() => {
    const el = scrollRef.current
    if (!el || !autoScrollRef.current) return
    el.scrollTop = el.scrollHeight
  }, [messages, currentTextAccumulator])

  const handleScroll = useCallback(() => {
    const el = scrollRef.current
    if (!el) return
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 100
    autoScrollRef.current = nearBottom
  }, [])

  const handleSend = useCallback(() => {
    const text = input.trim()
    if (!text || isStreaming || connectionStatus !== 'connected') return
    useChatStore.getState().addUserMessage(text)
    sendMessage(text)
    setInput('')
    autoScrollRef.current = true
  }, [input, isStreaming, connectionStatus, sendMessage])

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
      if (e.key === 'Enter' && !e.shiftKey) {
        e.preventDefault()
        handleSend()
      }
    },
    [handleSend],
  )

  // Group tool_call with its tool_result
  const groupedMessages = groupMessages(messages)

  if (!isOpen) {
    return (
      <Button
        variant="outline"
        size="sm"
        onClick={onToggle}
        className="absolute right-4 top-2 z-10"
      >
        <MessageSquare className="h-4 w-4" />
        <span>AI Chat</span>
      </Button>
    )
  }

  const statusColor =
    connectionStatus === 'connected'
      ? 'bg-green-500'
      : connectionStatus === 'connecting'
        ? 'bg-yellow-500'
        : 'bg-gray-400'

  return (
    <div className="flex h-full w-96 shrink-0 flex-col border-l border-border">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-2">
        <MessageSquare className="h-4 w-4 text-muted-foreground" />
        <span className="text-sm font-medium">AI Assistant</span>
        <span className={`ml-1 h-2 w-2 rounded-full ${statusColor}`} />
        <Button
          variant="ghost"
          size="icon-xs"
          onClick={onToggle}
          className="ml-auto"
        >
          <X className="h-4 w-4" />
        </Button>
      </div>

      {/* Messages */}
      <div
        ref={scrollRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto px-3 py-2"
      >
        {initializing && (
          <div className="flex items-center justify-center py-8 text-sm text-muted-foreground">
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Starting conversation...
          </div>
        )}

        {groupedMessages.map((item) => {
          if (item.type === 'tool_pair') {
            return (
              <ToolCallBlock
                key={item.toolCall.id}
                toolCall={item.toolCall}
                toolResult={item.toolResult}
              />
            )
          }
          return <ChatMessage key={item.message.id} message={item.message} />
        })}

        {/* Live streaming text */}
        {currentTextAccumulator && (
          <ChatMessage
            message={{ id: '__streaming__', kind: 'assistant_text', content: currentTextAccumulator }}
          />
        )}

        {isStreaming && !currentTextAccumulator && (
          <div className="flex items-center gap-2 py-2 text-sm text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin" />
            <span>Thinking...</span>
          </div>
        )}
      </div>

      {/* Input */}
      <div className="border-t border-border p-3">
        <div className="flex gap-2">
          <textarea
            ref={textareaRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder={
              connectionStatus !== 'connected'
                ? 'Connecting...'
                : 'Ask about the firmware...'
            }
            disabled={connectionStatus !== 'connected' || isStreaming}
            rows={1}
            className="field-sizing-content max-h-32 min-h-9 flex-1 resize-none rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring disabled:cursor-not-allowed disabled:opacity-50"
          />
          <Button
            size="icon"
            onClick={handleSend}
            disabled={
              !input.trim() ||
              isStreaming ||
              connectionStatus !== 'connected'
            }
          >
            <Send className="h-4 w-4" />
          </Button>
        </div>
      </div>
    </div>
  )
}

type GroupedItem =
  | {
      type: 'tool_pair'
      toolCall: Extract<ChatDisplayMessage, { kind: 'tool_call' }>
      toolResult?: Extract<ChatDisplayMessage, { kind: 'tool_result' }>
    }
  | { type: 'message'; message: ChatDisplayMessage }

function groupMessages(messages: ChatDisplayMessage[]): GroupedItem[] {
  const result: GroupedItem[] = []

  for (let i = 0; i < messages.length; i++) {
    const msg = messages[i]

    if (msg.kind === 'tool_call') {
      // Look ahead for matching tool_result
      const next = messages[i + 1]
      if (next?.kind === 'tool_result' && next.toolUseId === msg.toolUseId) {
        result.push({
          type: 'tool_pair',
          toolCall: msg as Extract<ChatDisplayMessage, { kind: 'tool_call' }>,
          toolResult: next as Extract<ChatDisplayMessage, { kind: 'tool_result' }>,
        })
        i++ // skip the tool_result
      } else {
        result.push({
          type: 'tool_pair',
          toolCall: msg as Extract<ChatDisplayMessage, { kind: 'tool_call' }>,
        })
      }
    } else if (msg.kind === 'tool_result') {
      // Orphan result (shouldn't happen normally), skip it
      continue
    } else {
      result.push({ type: 'message', message: msg })
    }
  }

  return result
}
