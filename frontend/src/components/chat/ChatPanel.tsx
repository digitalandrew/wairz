import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { MessageSquare, X, Send, Loader2, Paperclip, FileText, ChevronDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import { useChatStore } from '@/stores/chatStore'
import { useExplorerStore } from '@/stores/explorerStore'
import { useWebSocket } from '@/hooks/useWebSocket'
import { createConversation } from '@/api/chat'
import ChatMessage from './ChatMessage'
import ToolCallBlock from './ToolCallBlock'
import type { ChatDisplayMessage } from '@/types'
import { MODEL_OPTIONS } from '@/types'

interface ChatPanelProps {
  isOpen: boolean
  onToggle: () => void
}

export default function ChatPanel({ isOpen, onToggle }: ChatPanelProps) {
  const { projectId } = useParams<{ projectId: string }>()
  const conversationId = useChatStore((s) => s.conversationId)
  const messages = useChatStore((s) => s.messages)
  const connectionStatus = useChatStore((s) => s.connectionStatus)
  const isStreaming = useChatStore((s) => s.isStreaming)
  const currentTextAccumulator = useChatStore((s) => s.currentTextAccumulator)
  const setConversationId = useChatStore((s) => s.setConversationId)
  const selectedModel = useChatStore((s) => s.selectedModel)
  const setSelectedModel = useChatStore((s) => s.setSelectedModel)
  const attachments = useChatStore((s) => s.attachments)
  const addAttachment = useChatStore((s) => s.addAttachment)
  const removeAttachment = useChatStore((s) => s.removeAttachment)
  const clearAttachments = useChatStore((s) => s.clearAttachments)

  const selectedPath = useExplorerStore((s) => s.selectedPath)
  const selectedNode = useExplorerStore((s) => s.selectedNode)

  const { sendMessage } = useWebSocket(projectId!, conversationId)

  const [input, setInput] = useState('')
  const [initializing, setInitializing] = useState(false)
  const [width, setWidth] = useState(384) // default w-96
  const [modelDropdownOpen, setModelDropdownOpen] = useState(false)
  const scrollRef = useRef<HTMLDivElement>(null)
  const autoScrollRef = useRef(true)
  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const draggingRef = useRef(false)

  // Resize drag handling
  const handleResizeStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    draggingRef.current = true
    const startX = e.clientX
    const startWidth = width

    const onMouseMove = (ev: MouseEvent) => {
      if (!draggingRef.current) return
      const newWidth = Math.min(Math.max(startWidth + (startX - ev.clientX), 280), 800)
      setWidth(newWidth)
    }

    const onMouseUp = () => {
      draggingRef.current = false
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'col-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [width])

  // Create conversation on first open if needed
  useEffect(() => {
    if (!isOpen || conversationId || initializing || !projectId) return
    setInitializing(true)
    createConversation(projectId, 'New chat')
      .then((c) => setConversationId(c.id))
      .catch(() => useChatStore.getState().addError('Failed to create conversation'))
      .finally(() => setInitializing(false))
  }, [isOpen, conversationId, projectId, initializing, setConversationId])

  // Auto-send pending message when chat connects
  useEffect(() => {
    if (connectionStatus !== 'connected' || isStreaming) return
    const msg = useChatStore.getState().consumePendingMessage()
    if (!msg) return
    const model = useChatStore.getState().selectedModel
    useChatStore.getState().addUserMessage(msg)
    sendMessage(msg, undefined, model)
    autoScrollRef.current = true
  }, [connectionStatus, isStreaming, sendMessage])

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

  const handleAttach = useCallback(() => {
    if (!selectedPath || !selectedNode || selectedNode.fileType !== 'file') return
    addAttachment({ path: selectedPath, name: selectedNode.name })
  }, [selectedPath, selectedNode, addAttachment])

  const handleSend = useCallback(() => {
    const text = input.trim()
    if (!text || isStreaming || connectionStatus !== 'connected') return
    const currentAttachments = useChatStore.getState().attachments
    const model = useChatStore.getState().selectedModel
    useChatStore.getState().addUserMessage(
      text,
      currentAttachments.length ? currentAttachments : undefined,
    )
    sendMessage(text, currentAttachments.length ? currentAttachments : undefined, model)
    clearAttachments()
    setInput('')
    autoScrollRef.current = true
  }, [input, isStreaming, connectionStatus, sendMessage, clearAttachments])

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
        className="absolute bottom-4 right-4 z-10"
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
    <div className="relative flex h-full shrink-0 flex-col border-l border-border" style={{ width }}>
      {/* Resize handle */}
      <div
        onMouseDown={handleResizeStart}
        className="absolute inset-y-0 left-0 z-10 w-1 cursor-col-resize hover:bg-primary/30 active:bg-primary/50"
      />
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

      {/* Model selector */}
      <div className="relative border-b border-border px-3 py-1.5">
        <button
          type="button"
          onClick={() => setModelDropdownOpen((o) => !o)}
          className="flex w-full items-center gap-1.5 rounded-md px-2 py-1 text-xs text-muted-foreground hover:bg-accent hover:text-foreground"
        >
          <span className="font-medium text-foreground">
            {MODEL_OPTIONS.find((m) => m.id === selectedModel)?.label ?? 'Sonnet 4'}
          </span>
          <span className="text-muted-foreground">
            {MODEL_OPTIONS.find((m) => m.id === selectedModel)?.cost}
          </span>
          <ChevronDown className="ml-auto h-3 w-3" />
        </button>
        {modelDropdownOpen && (
          <>
            <div
              className="fixed inset-0 z-20"
              onClick={() => setModelDropdownOpen(false)}
            />
            <div className="absolute left-2 right-2 top-full z-30 mt-1 rounded-md border border-border bg-popover p-1 shadow-md">
              {MODEL_OPTIONS.map((m) => (
                <button
                  key={m.id}
                  type="button"
                  onClick={() => {
                    setSelectedModel(m.id)
                    setModelDropdownOpen(false)
                  }}
                  className={`flex w-full flex-col gap-0.5 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent ${
                    m.id === selectedModel ? 'bg-accent/50' : ''
                  }`}
                >
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{m.label}</span>
                    <span
                      className={`rounded px-1.5 py-0.5 text-[10px] font-medium leading-none ${
                        m.cost === 'Least expensive'
                          ? 'bg-green-500/15 text-green-600 dark:text-green-400'
                          : m.cost === 'Moderate'
                            ? 'bg-yellow-500/15 text-yellow-600 dark:text-yellow-400'
                            : 'bg-red-500/15 text-red-600 dark:text-red-400'
                      }`}
                    >
                      {m.cost}
                    </span>
                  </div>
                  <span className="text-muted-foreground">{m.description}</span>
                </button>
              ))}
            </div>
          </>
        )}
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
        {/* Attachment chips */}
        {attachments.length > 0 && (
          <div className="mb-2 flex flex-wrap gap-1">
            {attachments.map((att) => (
              <span
                key={att.path}
                className="inline-flex items-center gap-1 rounded-md bg-primary/10 px-2 py-0.5 text-xs text-primary"
              >
                <FileText className="h-3 w-3" />
                {att.name}
                <button
                  type="button"
                  onClick={() => removeAttachment(att.path)}
                  className="ml-0.5 rounded hover:bg-primary/20"
                >
                  <X className="h-3 w-3" />
                </button>
              </span>
            ))}
          </div>
        )}
        <div className="flex gap-2">
          <Button
            variant="ghost"
            size="icon"
            onClick={handleAttach}
            disabled={
              !selectedPath ||
              !selectedNode ||
              selectedNode.fileType !== 'file' ||
              attachments.length >= 5
            }
            title={
              !selectedPath
                ? 'Select a file in the explorer first'
                : attachments.length >= 5
                  ? 'Max 5 attachments'
                  : `Attach ${selectedNode?.name ?? 'file'}`
            }
            className="shrink-0"
          >
            <Paperclip className="h-4 w-4" />
          </Button>
          <textarea
            ref={textareaRef}
            data-chat-input
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
