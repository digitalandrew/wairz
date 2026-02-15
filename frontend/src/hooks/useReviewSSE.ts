import { useEffect, useRef } from 'react'
import { buildReviewSSEUrl } from '@/api/reviews'
import { useReviewStore } from '@/stores/reviewStore'

export function useReviewSSE(projectId: string, reviewId: string | null) {
  const sourceRef = useRef<EventSource | null>(null)

  useEffect(() => {
    if (!reviewId) return

    const url = buildReviewSSEUrl(projectId, reviewId)
    const source = new EventSource(url)
    sourceRef.current = source

    source.addEventListener('review_status_change', (e) => {
      const data = JSON.parse(e.data)
      useReviewStore.getState().updateReviewStatus(data.status)
    })

    source.addEventListener('agent_status_change', (e) => {
      const data = JSON.parse(e.data)
      useReviewStore.getState().updateAgentStatus(
        data.agent_id,
        data.status,
        data.tool_calls_count,
        data.findings_count,
        data.error,
      )
    })

    source.addEventListener('agent_tool_call', (e) => {
      const data = JSON.parse(e.data)
      useReviewStore.getState().updateAgentToolCall(
        data.agent_id,
        data.tool,
        data.tool_calls_count,
      )
    })

    source.addEventListener('agent_finding', (e) => {
      const data = JSON.parse(e.data)
      useReviewStore.getState().addLiveFinding(
        data.agent_id,
        data.category,
        data.title,
        data.severity,
        data.findings_count,
      )
    })

    source.addEventListener('review_complete', (e) => {
      const data = JSON.parse(e.data)
      useReviewStore.getState().updateReviewStatus(data.status)
      source.close()
    })

    source.addEventListener('heartbeat', () => {
      // keep-alive, nothing to do
    })

    source.onerror = () => {
      // EventSource will auto-reconnect for non-fatal errors.
      // On fatal close, check if review was already completed.
    }

    return () => {
      source.close()
      sourceRef.current = null
    }
  }, [projectId, reviewId])
}
