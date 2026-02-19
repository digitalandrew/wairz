import { useState, useEffect } from 'react'
import { useParams } from 'react-router-dom'
import { Loader2, AlertTriangle } from 'lucide-react'
import { getComponentMap } from '@/api/componentMap'
import type { ComponentGraph } from '@/types'
import ComponentMap from '@/components/component-map/ComponentMap'

export default function ComponentMapPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [graph, setGraph] = useState<ComponentGraph | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

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
    }
  }, [projectId])

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
      <div className="relative min-w-0 flex-1">
        <ComponentMap graph={graph} />
      </div>
    </div>
  )
}
