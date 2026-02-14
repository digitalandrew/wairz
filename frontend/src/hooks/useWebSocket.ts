import { useEffect, useRef, useCallback } from 'react'
import { buildWebSocketURL } from '@/api/chat'
import { useChatStore } from '@/stores/chatStore'
import type { ChatAttachment, WSEvent } from '@/types'

export function useWebSocket(projectId: string, conversationId: string | null) {
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Use ref to always have latest conversationId without re-creating effect
  const conversationIdRef = useRef(conversationId)
  conversationIdRef.current = conversationId

  const connect = useCallback(() => {
    if (!conversationId) return

    const store = useChatStore.getState()
    store.setConnectionStatus('connecting')

    const url = buildWebSocketURL(projectId, conversationId)
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      useChatStore.getState().setConnectionStatus('connected')
    }

    ws.onmessage = (evt) => {
      let event: WSEvent
      try {
        event = JSON.parse(evt.data) as WSEvent
      } catch {
        return
      }

      const actions = useChatStore.getState()

      switch (event.type) {
        case 'assistant_text':
          actions.appendAssistantText(event.content)
          break
        case 'tool_call':
          actions.finalizeAssistantText()
          actions.addToolCall(event.tool, event.tool_use_id, event.input)
          break
        case 'tool_result':
          actions.addToolResult(event.tool, event.tool_use_id, event.output)
          break
        case 'error':
          actions.addError(event.content)
          break
        case 'done':
          actions.finalizeAssistantText()
          actions.stopStreaming()
          break
      }
    }

    ws.onclose = () => {
      useChatStore.getState().setConnectionStatus('disconnected')
      wsRef.current = null
      // Reconnect if conversationId is still set
      if (conversationIdRef.current) {
        reconnectTimer.current = setTimeout(() => {
          if (conversationIdRef.current) {
            connect()
          }
        }, 3000)
      }
    }

    ws.onerror = () => {
      // onclose will fire after this, which handles reconnection
    }
  }, [projectId, conversationId])

  useEffect(() => {
    connect()

    return () => {
      if (reconnectTimer.current) {
        clearTimeout(reconnectTimer.current)
        reconnectTimer.current = null
      }
      if (wsRef.current) {
        wsRef.current.close()
        wsRef.current = null
      }
    }
  }, [connect])

  const sendMessage = useCallback(
    (content: string, attachments?: ChatAttachment[]) => {
      const ws = wsRef.current
      if (!ws || ws.readyState !== WebSocket.OPEN) return
      useChatStore.getState().startStreaming()
      const payload: Record<string, unknown> = { type: 'user_message', content }
      if (attachments?.length) {
        payload.attachments = attachments.map((a) => a.path)
      }
      ws.send(JSON.stringify(payload))
    },
    [],
  )

  return { sendMessage }
}
