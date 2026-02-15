import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { Loader2, AlertTriangle } from 'lucide-react'
import { getComponentMap } from '@/api/componentMap'
import { useChatStore } from '@/stores/chatStore'
import type { ComponentGraph } from '@/types'
import ComponentMap from '@/components/component-map/ComponentMap'
import ChatPanel from '@/components/chat/ChatPanel'

export default function ComponentMapPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const resetChat = useChatStore((s) => s.reset)
  const [graph, setGraph] = useState<ComponentGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [chatOpen, setChatOpen] = useState(false)

  useEffect(() => {
    if (!projectId) return

    let cancelled = false
    setLoading(true)
    setError(null)

    getComponentMap(projectId)
      .then((data) => {
        if (!cancelled) setGraph(data)
      })
      .catch((err) => {
        if (!cancelled) {
          const msg = err.response?.data?.detail ?? err.message ?? 'Failed to load component map'
          setError(msg)
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })

    return () => {
      cancelled = true
      resetChat()
    }
  }, [projectId, resetChat])

  const handleRequestChat = useCallback(() => {
    setChatOpen(true)
  }, [])

  if (loading) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <Loader2 className="h-8 w-8 animate-spin" />
          <div className="text-sm">Building component map...</div>
          <div className="text-xs">This may take a few seconds on first load</div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="flex flex-col items-center gap-3 text-muted-foreground">
          <AlertTriangle className="h-8 w-8 text-destructive" />
          <div className="text-sm">{error}</div>
        </div>
      </div>
    )
  }

  if (!graph || graph.nodes.length === 0) {
    return (
      <div className="-m-6 flex h-[calc(100vh-3.5rem)] items-center justify-center">
        <div className="text-sm text-muted-foreground">
          No components found. Make sure firmware is unpacked first.
        </div>
      </div>
    )
  }

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Main panel: component map */}
      <div className="relative min-w-0 flex-1">
        <ComponentMap graph={graph} onRequestChat={handleRequestChat} />

        {/* Chat toggle — bottom-right */}
        {!chatOpen && (
          <ChatPanel isOpen={false} onToggle={() => setChatOpen(true)} />
        )}
      </div>

      {/* Right panel: chat */}
      {chatOpen && (
        <ChatPanel isOpen={true} onToggle={() => setChatOpen(false)} />
      )}
    </div>
  )
}
