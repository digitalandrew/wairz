import { useCallback, useEffect, useRef, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Play,
  Square,
  Loader2,
  RefreshCw,
  TerminalSquare,
  Plus,
  Trash2,
  Cpu,
  Clock,
  AlertCircle,
  FileText,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Terminal } from '@xterm/xterm'
import { FitAddon } from '@xterm/addon-fit'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatDate } from '@/utils/format'
import {
  startEmulation,
  stopEmulation,
  listSessions,
  getSessionStatus,
  getSessionLogs,
  buildEmulationTerminalURL,
} from '@/api/emulation'
import { getFirmware } from '@/api/firmware'
import { useChatStore } from '@/stores/chatStore'
import ChatPanel from '@/components/chat/ChatPanel'
import KernelManager from '@/components/emulation/KernelManager'
import type {
  EmulationSession,
  EmulationMode,
  EmulationStatus,
  PortForward,
} from '@/types'
import '@xterm/xterm/css/xterm.css'

const STATUS_CONFIG: Record<EmulationStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  starting: { label: 'Starting', className: 'bg-yellow-500 text-black' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

export default function EmulationPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const resetChat = useChatStore((s) => s.reset)
  const [chatOpen, setChatOpen] = useState(false)

  const [sessions, setSessions] = useState<EmulationSession[]>([])
  const [loading, setLoading] = useState(true)
  const [starting, setStarting] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Start form state
  const [mode, setMode] = useState<EmulationMode>('user')
  const [binaryPath, setBinaryPath] = useState('')
  const [arguments_, setArguments] = useState('')
  const [portForwards, setPortForwards] = useState<PortForward[]>([])

  // Kernel selection (system mode)
  const [kernelName, setKernelName] = useState<string | null>(null)
  const [firmwareArch, setFirmwareArch] = useState<string | null>(null)
  const [firmwareKernelPath, setFirmwareKernelPath] = useState<string | null>(null)

  // Active session + terminal
  const [activeSession, setActiveSession] = useState<EmulationSession | null>(null)
  const [showTerminal, setShowTerminal] = useState(false)

  const loadSessions = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listSessions(projectId)
      setSessions(data)

      // Auto-select the first running session
      const running = data.find((s) => s.status === 'running')
      if (running && !activeSession) {
        setActiveSession(running)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [projectId, activeSession])

  useEffect(() => {
    loadSessions()
    return () => { resetChat() }
  }, [loadSessions, resetChat])

  // Fetch firmware architecture for kernel selection
  useEffect(() => {
    if (!projectId) return
    getFirmware(projectId)
      .then((fw) => {
        setFirmwareArch(fw.architecture ?? null)
        setFirmwareKernelPath(fw.kernel_path ?? null)
      })
      .catch(() => {})
  }, [projectId])

  // Poll for status updates (faster during active sessions)
  useEffect(() => {
    if (!projectId) return
    const hasActive = sessions.some((s) => s.status === 'running' || s.status === 'starting')
    if (!hasActive) return

    const interval = setInterval(loadSessions, 2000)
    return () => clearInterval(interval)
  }, [projectId, sessions, loadSessions])

  const handleStart = async () => {
    if (!projectId) return
    if (mode === 'user' && !binaryPath.trim()) {
      setError('Binary path is required for user-mode emulation')
      return
    }

    setStarting(true)
    setError(null)

    try {
      const session = await startEmulation(projectId, {
        mode,
        binary_path: mode === 'user' ? binaryPath.trim() : undefined,
        arguments: mode === 'user' && arguments_.trim() ? arguments_.trim() : undefined,
        port_forwards: mode === 'system' && portForwards.length > 0 ? portForwards : undefined,
        kernel_name: mode === 'system' && kernelName ? kernelName : undefined,
      })
      setActiveSession(session)
      if (session.status === 'running' || session.status === 'error') {
        setShowTerminal(session.status === 'running')
      }
      await loadSessions()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to start emulation'
      // Try to extract API error detail
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const resp = (err as { response?: { data?: { detail?: string } } }).response
        if (resp?.data?.detail) {
          setError(resp.data.detail)
        } else {
          setError(msg)
        }
      } else {
        setError(msg)
      }
    } finally {
      setStarting(false)
    }
  }

  const handleStop = async (sessionId: string) => {
    if (!projectId) return
    try {
      await stopEmulation(projectId, sessionId)
      if (activeSession?.id === sessionId) {
        setShowTerminal(false)
        setActiveSession(null)
      }
      await loadSessions()
    } catch {
      // ignore
    }
  }

  const handleConnect = async (session: EmulationSession) => {
    if (!projectId) return
    // Refresh status
    try {
      const updated = await getSessionStatus(projectId, session.id)
      setActiveSession(updated)
      if (updated.status === 'running') {
        setShowTerminal(true)
      }
    } catch {
      setActiveSession(session)
      if (session.status === 'running') {
        setShowTerminal(true)
      }
    }
  }

  const addPortForward = () => {
    setPortForwards([...portForwards, { host: 8080, guest: 80 }])
  }

  const removePortForward = (index: number) => {
    setPortForwards(portForwards.filter((_, i) => i !== index))
  }

  const updatePortForward = (index: number, field: 'host' | 'guest', value: number) => {
    const updated = [...portForwards]
    updated[index] = { ...updated[index], [field]: value }
    setPortForwards(updated)
  }

  const handleRequestChat = useCallback(() => {
    setChatOpen(true)
  }, [])

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      {/* Header */}
      <div className="border-b border-border bg-background px-6 py-4">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-semibold">Firmware Emulation</h1>
            <p className="text-sm text-muted-foreground">
              Run firmware binaries or boot the full OS using QEMU
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={loadSessions}>
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — controls + session list */}
        <div className="w-96 shrink-0 overflow-y-auto border-r border-border p-4 space-y-6">
          {/* Start Emulation Form */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Start Emulation
            </h2>

            {/* Mode selector */}
            <div className="flex gap-2">
              <button
                onClick={() => setMode('user')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium transition-colors ${
                  mode === 'user'
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/50'
                }`}
              >
                <Cpu className="mb-1 inline h-4 w-4" /> User Mode
              </button>
              <button
                onClick={() => setMode('system')}
                className={`flex-1 rounded-md border px-3 py-2 text-sm font-medium transition-colors ${
                  mode === 'system'
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/50'
                }`}
              >
                <TerminalSquare className="mb-1 inline h-4 w-4" /> System Mode
              </button>
            </div>

            <p className="text-xs text-muted-foreground">
              {mode === 'user'
                ? 'Run a single binary in a chroot. Fast, good for testing specific programs.'
                : 'Boot the full firmware OS. Slower, good for testing services and network.'}
            </p>

            {/* User mode fields */}
            {mode === 'user' && (
              <>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    Binary Path *
                  </label>
                  <input
                    type="text"
                    value={binaryPath}
                    onChange={(e) => setBinaryPath(e.target.value)}
                    placeholder="/usr/sbin/httpd"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-xs font-medium text-muted-foreground">
                    Arguments
                  </label>
                  <input
                    type="text"
                    value={arguments_}
                    onChange={(e) => setArguments(e.target.value)}
                    placeholder="--help"
                    className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                  />
                </div>
              </>
            )}

            {/* System mode fields */}
            {mode === 'system' && (
              <>
              <KernelManager
                firmwareArchitecture={firmwareArch}
                firmwareKernelPath={firmwareKernelPath}
                onKernelSelect={setKernelName}
                selectedKernel={kernelName}
                onRequestChat={handleRequestChat}
              />
              <div>
                <div className="mb-2 flex items-center justify-between">
                  <label className="text-xs font-medium text-muted-foreground">
                    Port Forwarding
                  </label>
                  <button
                    onClick={addPortForward}
                    className="flex items-center gap-1 text-xs text-primary hover:underline"
                  >
                    <Plus className="h-3 w-3" /> Add
                  </button>
                </div>
                {portForwards.length === 0 && (
                  <p className="text-xs text-muted-foreground/60">No port forwards configured</p>
                )}
                {portForwards.map((pf, i) => (
                  <div key={i} className="mb-1.5 flex items-center gap-2">
                    <input
                      type="number"
                      value={pf.host}
                      onChange={(e) => updatePortForward(i, 'host', parseInt(e.target.value) || 0)}
                      className="w-20 rounded border border-border bg-background px-2 py-1 text-xs"
                      placeholder="Host"
                    />
                    <span className="text-xs text-muted-foreground">→</span>
                    <input
                      type="number"
                      value={pf.guest}
                      onChange={(e) => updatePortForward(i, 'guest', parseInt(e.target.value) || 0)}
                      className="w-20 rounded border border-border bg-background px-2 py-1 text-xs"
                      placeholder="Guest"
                    />
                    <button
                      onClick={() => removePortForward(i)}
                      className="text-muted-foreground hover:text-destructive"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                ))}
              </div>
              </>
            )}

            {error && (
              <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {error}
              </div>
            )}

            <Button
              onClick={handleStart}
              disabled={starting}
              className="w-full"
            >
              {starting ? (
                <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
              ) : (
                <Play className="mr-1.5 h-4 w-4" />
              )}
              {starting ? 'Starting...' : 'Start Emulation'}
            </Button>
          </div>

          {/* Session list */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Sessions ({sessions.length})
            </h2>

            {sessions.length === 0 && (
              <p className="text-xs text-muted-foreground/60">No emulation sessions yet</p>
            )}

            {sessions.map((session) => (
              <SessionCard
                key={session.id}
                session={session}
                isActive={activeSession?.id === session.id}
                projectId={projectId!}
                onConnect={() => handleConnect(session)}
                onStop={() => handleStop(session.id)}
              />
            ))}
          </div>
        </div>

        {/* Center panel — terminal */}
        <div className="relative flex-1 bg-[#0a0a0b]">
          {showTerminal && activeSession && projectId ? (
            <EmulationTerminal
              projectId={projectId}
              session={activeSession}
              onClose={() => setShowTerminal(false)}
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              <div className="text-center">
                <TerminalSquare className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                <p>Start an emulation session or connect to a running one</p>
                <p className="mt-1 text-xs text-muted-foreground/60">
                  The terminal will appear here when a session is active
                </p>
              </div>
            </div>
          )}

          {/* Chat toggle — bottom-right */}
          {!chatOpen && (
            <ChatPanel isOpen={false} onToggle={() => setChatOpen(true)} />
          )}
        </div>

        {/* Right panel — AI chat */}
        {chatOpen && (
          <ChatPanel isOpen={true} onToggle={() => setChatOpen(false)} />
        )}
      </div>
    </div>
  )
}

// ── Session card with error display and log viewer ──

interface SessionCardProps {
  session: EmulationSession
  isActive: boolean
  projectId: string
  onConnect: () => void
  onStop: () => void
}

function SessionCard({ session, isActive, projectId, onConnect, onStop }: SessionCardProps) {
  const statusCfg = STATUS_CONFIG[session.status] || STATUS_CONFIG.stopped
  const [showLogs, setShowLogs] = useState(false)
  const [logs, setLogs] = useState<string | null>(null)
  const [logsLoading, setLogsLoading] = useState(false)

  const handleViewLogs = async () => {
    if (showLogs) {
      setShowLogs(false)
      return
    }
    setShowLogs(true)
    setLogsLoading(true)
    try {
      const logText = await getSessionLogs(projectId, session.id)
      setLogs(logText)
    } catch {
      setLogs('Failed to fetch logs')
    } finally {
      setLogsLoading(false)
    }
  }

  return (
    <div
      className={`rounded-lg border p-3 transition-colors ${
        isActive
          ? 'border-primary/50 bg-primary/5'
          : 'border-border hover:border-border/80'
      }`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge className={`text-[10px] ${statusCfg.className}`}>
            {statusCfg.label}
          </Badge>
          <span className="text-xs font-medium">
            {session.mode === 'user' ? 'User' : 'System'} Mode
          </span>
        </div>
        {session.architecture && (
          <Badge variant="outline" className="text-[10px]">
            {session.architecture}
          </Badge>
        )}
      </div>

      {session.binary_path && (
        <p className="mt-1 truncate text-xs text-muted-foreground font-mono">
          {session.binary_path}
        </p>
      )}

      <div className="mt-1 flex items-center gap-2 text-[10px] text-muted-foreground">
        <Clock className="h-3 w-3" />
        {formatDate(session.created_at)}
      </div>

      {/* Error message — prominent display */}
      {session.error_message && (
        <div className="mt-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
          <div className="flex items-start gap-2">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div className="min-w-0">
              <p className="font-medium">Emulation failed</p>
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-words text-[11px] opacity-90 font-mono">
                {session.error_message}
              </pre>
            </div>
          </div>
        </div>
      )}

      <div className="mt-2 flex flex-wrap gap-2">
        {session.status === 'running' && (
          <>
            <Button
              variant="outline"
              size="sm"
              className="h-7 text-xs"
              onClick={onConnect}
            >
              <TerminalSquare className="mr-1 h-3 w-3" />
              Connect
            </Button>
            <Button
              variant="destructive"
              size="sm"
              className="h-7 text-xs"
              onClick={onStop}
            >
              <Square className="mr-1 h-3 w-3" />
              Stop
            </Button>
          </>
        )}
        {/* View Logs button — available for any session with a container */}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 text-xs"
          onClick={handleViewLogs}
        >
          <FileText className="mr-1 h-3 w-3" />
          Logs
          {showLogs ? <ChevronUp className="ml-1 h-3 w-3" /> : <ChevronDown className="ml-1 h-3 w-3" />}
        </Button>
      </div>

      {/* Expandable log viewer */}
      {showLogs && (
        <div className="mt-2 rounded-md border border-border bg-[#0a0a0b] p-2">
          {logsLoading ? (
            <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
              <Loader2 className="h-3 w-3 animate-spin" />
              Loading logs...
            </div>
          ) : (
            <pre className="max-h-60 overflow-auto whitespace-pre-wrap break-words text-[11px] text-zinc-300 font-mono">
              {logs || 'No logs available'}
            </pre>
          )}
        </div>
      )}
    </div>
  )
}

// ── Embedded terminal component ──

interface EmulationTerminalProps {
  projectId: string
  session: EmulationSession
  onClose: () => void
}

function EmulationTerminal({ projectId, session, onClose }: EmulationTerminalProps) {
  const containerRef = useRef<HTMLDivElement>(null)
  const termRef = useRef<Terminal | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!containerRef.current || session.status !== 'running') return

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
    termRef.current = term

    term.open(containerRef.current)
    requestAnimationFrame(() => fitAddon.fit())

    // Connect WebSocket
    const url = buildEmulationTerminalURL(projectId, session.id)
    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
    }

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data)
        if (msg.type === 'output' && msg.data) {
          term.write(msg.data)
        } else if (msg.type === 'error') {
          term.write(`\r\n\x1b[31mError: ${msg.data}\x1b[0m\r\n`)
        }
      } catch {
        term.write(event.data)
      }
    }

    ws.onclose = () => {
      term.write('\r\n\x1b[90m[Session disconnected]\x1b[0m\r\n')
      // Fetch logs to show what happened
      getSessionLogs(projectId, session.id)
        .then((logText) => {
          if (logText && logText !== '(no log available)') {
            term.write('\r\n\x1b[33m--- QEMU Startup Log ---\x1b[0m\r\n')
            term.write(logText.replace(/\n/g, '\r\n'))
            term.write('\r\n\x1b[33m--- End Log ---\x1b[0m\r\n')
          }
        })
        .catch(() => {})
    }

    const onData = term.onData((data: string) => {
      if (ws.readyState === WebSocket.OPEN) {
        ws.send(JSON.stringify({ type: 'input', data }))
      }
    })

    return () => {
      onData.dispose()
      if (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING) {
        ws.close()
      }
      wsRef.current = null
      termRef.current = null
      fitAddonRef.current = null
      term.dispose()
    }
  }, [projectId, session.id, session.status])

  // Resize observer
  useEffect(() => {
    if (!containerRef.current) return

    const observer = new ResizeObserver(() => {
      const fitAddon = fitAddonRef.current
      const term = termRef.current
      const ws = wsRef.current
      if (!fitAddon || !term) return
      try {
        fitAddon.fit()
        if (ws && ws.readyState === WebSocket.OPEN) {
          ws.send(JSON.stringify({ type: 'resize', cols: term.cols, rows: term.rows }))
        }
      } catch {
        // ignore
      }
    })
    observer.observe(containerRef.current)
    return () => observer.disconnect()
  }, [])

  return (
    <div className="flex h-full flex-col">
      {/* Terminal header */}
      <div className="flex items-center gap-2 border-b border-border bg-[#0a0a0b] px-3 py-1.5">
        <TerminalSquare className="h-3.5 w-3.5 text-muted-foreground" />
        <span className="text-xs font-medium text-muted-foreground">
          Emulation Terminal — {session.mode} mode
          {session.architecture ? ` (${session.architecture})` : ''}
        </span>
        <Badge
          className={`ml-auto text-[10px] ${STATUS_CONFIG[session.status]?.className || ''}`}
        >
          {session.status}
        </Badge>
        <button
          onClick={onClose}
          className="rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
          title="Close terminal"
        >
          <Square className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Terminal container */}
      <div ref={containerRef} className="flex-1 px-1 py-1" />
    </div>
  )
}
