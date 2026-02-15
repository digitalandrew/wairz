import { create } from 'zustand'
import type { SecurityReview, ReviewStatus, AgentStatus, ReviewCategory } from '@/types'
import { listReviews, getReview, createReview, cancelReview } from '@/api/reviews'

interface LiveFinding {
  id: string
  agentId: string
  category: string
  title: string
  severity: string
}

interface AgentLiveState {
  currentTool: string | null
  toolCallsCount: number
  findingsCount: number
}

interface ReviewState {
  reviews: SecurityReview[]
  currentReview: SecurityReview | null
  loading: boolean
  starting: boolean
  error: string | null
  liveFindings: LiveFinding[]
  agentLiveState: Record<string, AgentLiveState>
}

interface ReviewActions {
  fetchReviews: (projectId: string) => Promise<void>
  fetchReview: (projectId: string, reviewId: string) => Promise<void>
  startReview: (projectId: string, categories: ReviewCategory[]) => Promise<SecurityReview>
  cancelCurrentReview: (projectId: string) => Promise<void>
  updateReviewStatus: (status: ReviewStatus) => void
  updateAgentStatus: (
    agentId: string,
    status: AgentStatus,
    toolCallsCount?: number,
    findingsCount?: number,
    error?: string,
  ) => void
  updateAgentToolCall: (agentId: string, tool: string, toolCallsCount: number) => void
  addLiveFinding: (
    agentId: string,
    category: string,
    title: string,
    severity: string,
    findingsCount: number,
  ) => void
  clearReview: () => void
}

let findingCounter = 0

export const useReviewStore = create<ReviewState & ReviewActions>((set, get) => ({
  reviews: [],
  currentReview: null,
  loading: false,
  starting: false,
  error: null,
  liveFindings: [],
  agentLiveState: {},

  fetchReviews: async (projectId) => {
    set({ loading: true, error: null })
    try {
      const reviews = await listReviews(projectId)
      set({ reviews, loading: false })
    } catch (e) {
      set({ loading: false, error: extractError(e) })
    }
  },

  fetchReview: async (projectId, reviewId) => {
    set({ loading: true, error: null })
    try {
      const review = await getReview(projectId, reviewId)
      set({ currentReview: review, loading: false })
    } catch (e) {
      set({ loading: false, error: extractError(e) })
    }
  },

  startReview: async (projectId, categories) => {
    set({ starting: true, error: null, liveFindings: [], agentLiveState: {} })
    try {
      const review = await createReview(projectId, categories)
      set((s) => ({
        starting: false,
        currentReview: review,
        reviews: [review, ...s.reviews],
      }))
      return review
    } catch (e) {
      set({ starting: false, error: extractError(e) })
      throw e
    }
  },

  cancelCurrentReview: async (projectId) => {
    const review = get().currentReview
    if (!review) return
    try {
      await cancelReview(projectId, review.id)
    } catch (e) {
      set({ error: extractError(e) })
    }
  },

  updateReviewStatus: (status) => {
    set((s) => {
      if (!s.currentReview) return s
      return {
        currentReview: { ...s.currentReview, status },
      }
    })
  },

  updateAgentStatus: (agentId, status, toolCallsCount, findingsCount, error) => {
    set((s) => {
      if (!s.currentReview) return s
      const agents = s.currentReview.agents.map((a) =>
        a.id === agentId
          ? {
              ...a,
              status,
              tool_calls_count: toolCallsCount ?? a.tool_calls_count,
              findings_count: findingsCount ?? a.findings_count,
              error_message: error ?? a.error_message,
            }
          : a,
      )
      return {
        currentReview: { ...s.currentReview, agents },
      }
    })
  },

  updateAgentToolCall: (agentId, tool, toolCallsCount) => {
    set((s) => ({
      agentLiveState: {
        ...s.agentLiveState,
        [agentId]: {
          currentTool: tool,
          toolCallsCount,
          findingsCount: s.agentLiveState[agentId]?.findingsCount ?? 0,
        },
      },
    }))
  },

  addLiveFinding: (agentId, category, title, severity, findingsCount) => {
    findingCounter++
    set((s) => ({
      liveFindings: [
        { id: `lf-${findingCounter}`, agentId, category, title, severity },
        ...s.liveFindings,
      ].slice(0, 50), // Keep latest 50
      agentLiveState: {
        ...s.agentLiveState,
        [agentId]: {
          currentTool: s.agentLiveState[agentId]?.currentTool ?? null,
          toolCallsCount: s.agentLiveState[agentId]?.toolCallsCount ?? 0,
          findingsCount,
        },
      },
    }))
  },

  clearReview: () => {
    set({ currentReview: null, liveFindings: [], agentLiveState: {}, error: null })
  },
}))

function extractError(e: unknown): string {
  if (e && typeof e === 'object' && 'response' in e) {
    const resp = (e as { response?: { data?: { detail?: string } } }).response
    if (resp?.data?.detail) return resp.data.detail
  }
  if (e instanceof Error) return e.message
  return 'An unexpected error occurred'
}
