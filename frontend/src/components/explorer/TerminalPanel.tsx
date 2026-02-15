import { useEffect, useRef, useState, useCallback } from 'react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { X, TerminalSquare } from 'lucide-react'
import { useTerminalWebSocket } from '@/hooks/useTerminalWebSocket'
import '@xterm/xterm/css/xterm.css'

interface TerminalPanelProps {
  projectId: string | undefined
  isOpen: boolean
  onClose: () => void
}

export default function TerminalPanel({ projectId, isOpen, onClose }: TerminalPanelProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const [terminal, setTerminal] = useState<Terminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)

  const { sendResize } = useTerminalWebSocket({ projectId, terminal, isOpen })

  // Initialize xterm.js
  useEffect(() => {
    if (!isOpen || !containerRef.current) return

    const term = new Terminal({
      cursorBlink: true,
      fontSize: 13,
      fontFamily: 'ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, monospace',
      theme: {
        background: '#0a0a0b',
        foreground: '#e4e4e7',
        cursor: '#e4e4e7',
        selectionBackground: '#27272a',
        black: '#09090b',
        red: '#ef4444',
        green: '#22c55e',
        yellow: '#eab308',
        blue: '#3b82f6',
        magenta: '#a855f7',
        cyan: '#06b6d4',
        white: '#e4e4e7',
        brightBlack: '#52525b',
        brightRed: '#f87171',
        brightGreen: '#4ade80',
        brightYellow: '#facc15',
        brightBlue: '#60a5fa',
        brightMagenta: '#c084fc',
        brightCyan: '#22d3ee',
        brightWhite: '#fafafa',
      },
      scrollback: 5000,
      convertEol: true,
    })

    const fitAddon = new FitAddon()
    term.loadAddon(fitAddon)
    fitAddonRef.current = fitAddon

    term.open(containerRef.current)

    // Fit after a small delay to ensure container has layout
    requestAnimationFrame(() => {
      fitAddon.fit()
    })

    setTerminal(term)

    return () => {
      setTerminal(null)
      fitAddonRef.current = null
      term.dispose()
    }
  }, [isOpen])

  // Resize observer to keep terminal fitted
  const handleResize = useCallback(() => {
    const fitAddon = fitAddonRef.current
    if (!fitAddon || !terminal) return
    try {
      fitAddon.fit()
      sendResize(terminal.cols, terminal.rows)
    } catch {
      // fit() can throw if container has zero dimensions
    }
  }, [terminal, sendResize])

  useEffect(() => {
    if (!containerRef.current || !isOpen) return

    const observer = new ResizeObserver(() => {
      handleResize()
    })
    observer.observe(containerRef.current)

    return () => observer.disconnect()
  }, [isOpen, handleResize])

  if (!isOpen) return null

  return (
    <div className="flex h-full flex-col bg-[#0a0a0b]">
      {/* Header */}
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5">
        <TerminalSquare className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium text-muted-foreground">Terminal</span>
        <button
          onClick={onClose}
          className="ml-auto rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          title="Close terminal"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Terminal container */}
      <div ref={containerRef} className="flex-1 px-1 py-1" />
    </div>
  )
}
