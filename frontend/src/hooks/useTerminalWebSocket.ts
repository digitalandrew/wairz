import { useEffect, useRef, useCallback } from 'react'
import type { Terminal } from '@xterm/xterm'
import { buildTerminalWebSocketURL } from '@/api/terminal'

interface UseTerminalWebSocketOptions {
  projectId: string | undefined
  terminal: Terminal | null
  isOpen: boolean
}

export function useTerminalWebSocket({
  projectId,
  terminal,
  isOpen,
}: UseTerminalWebSocketOptions) {
  const wsRef = useRef<WebSocket | null>(null)
  const connectedRef = useRef(false)

  const sendResize = useCallback((cols: number, rows: number) => {
    const ws = wsRef.current
    if (ws && ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols, rows }))
    }
  }, [])

  useEffect(() => {
    if (!isOpen || !projectId || !terminal) return

    const url = buildTerminalWebSocketURL(projectId)
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      connectedRef.current = true
      // Send initial size
      sendResize(terminal.cols, terminal.rows)
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'output' && msg.data) {
          terminal.write(msg.data)
        } else if (msg.type === 'error') {
          terminal.write(`\r\n\x1b[31mError: ${msg.data}\x1b[0m\r\n`)
        }
      } catch {
        // Non-JSON message, write raw
        terminal.write(event.data)
      }
    }

    ws.onclose = () => {
      connectedRef.current = false
      terminal.write('\r\n\x1b[90m[Session ended]\x1b[0m\r\n')
    }

    ws.onerror = () => {
      connectedRef.current = false
    }

    // Forward keystrokes to backend
    const onData = terminal.onData((data: string) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
    })

    return () => {
      onData.dispose()
      connectedRef.current = false
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
      wsRef.current = null
    }
  }, [isOpen, projectId, terminal, sendResize])

  return { sendResize }
}
