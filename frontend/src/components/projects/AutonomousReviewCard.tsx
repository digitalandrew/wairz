import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import {
  Shield,
  Loader2,
  CheckCircle2,
  XCircle,
  AlertTriangle,
  Ban,
  Play,
  Square,
  MessageSquare,
  FileDown,
  ChevronDown,
  ChevronRight,
  Wrench,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Checkbox } from '@/components/ui/checkbox'
import { Progress } from '@/components/ui/progress'
import { useReviewStore } from '@/stores/reviewStore'
import { useReviewSSE } from '@/hooks/useReviewSSE'
import type {
  ReviewCategory,
  ReviewCategoryInfo,
  AgentStatus,
  SecurityReview,
  ReviewAgent,
} from '@/types'
import { REVIEW_CATEGORIES } from '@/types'

interface AutonomousReviewCardProps {
  projectId: string
}

export default function AutonomousReviewCard({ projectId }: AutonomousReviewCardProps) {
  const {
    reviews,
    currentReview,
    loading,
    starting,
    error,
    liveFindings,
    agentLiveState,
    fetchReviews,
    startReview,
    cancelCurrentReview,
    clearReview,
  } = useReviewStore()

  const [selectedCategories, setSelectedCategories] = useState<Set<ReviewCategory>>(() => {
    const defaults = new Set<ReviewCategory>()
    for (const cat of REVIEW_CATEGORIES) {
      if (cat.defaultSelected) defaults.add(cat.id)
    }
    return defaults
  })
  const [showFindings, setShowFindings] = useState(true)

  // Load existing reviews on mount
  useEffect(() => {
    fetchReviews(projectId)
    return () => clearReview()
  }, [projectId, fetchReviews, clearReview])

  // Auto-select latest active review
  useEffect(() => {
    if (!currentReview && reviews.length > 0) {
      const active = reviews.find((r) => r.status === 'running' || r.status === 'pending')
      if (active) {
        useReviewStore.setState({ currentReview: active })
      }
    }
  }, [reviews, currentReview])

  // SSE connection for active review
  useReviewSSE(
    projectId,
    currentReview && (currentReview.status === 'running' || currentReview.status === 'pending')
      ? currentReview.id
      : null,
  )

  const toggleCategory = useCallback((cat: ReviewCategory) => {
    setSelectedCategories((prev) => {
      const next = new Set(prev)
      if (next.has(cat)) {
        next.delete(cat)
      } else {
        next.add(cat)
      }
      return next
    })
  }, [])

  const handleStart = async () => {
    const cats = Array.from(selectedCategories)
    if (cats.length === 0) return
    try {
      await startReview(projectId, cats)
    } catch {
      // error shown via store
    }
  }

  const handleCancel = () => {
    cancelCurrentReview(projectId)
  }

  const handleNewReview = () => {
    clearReview()
  }

  // Determine which view to show
  const isActive = currentReview && (currentReview.status === 'running' || currentReview.status === 'pending')
  const isComplete = currentReview && (currentReview.status === 'completed' || currentReview.status === 'failed' || currentReview.status === 'cancelled')

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <Shield className="h-4 w-4" />
          Autonomous Security Review
        </CardTitle>
      </CardHeader>
      <CardContent>
        {!currentReview && !loading && (
          <SelectionView
            categories={REVIEW_CATEGORIES}
            selected={selectedCategories}
            onToggle={toggleCategory}
            onStart={handleStart}
            starting={starting}
            error={error}
          />
        )}

        {isActive && (
          <RunningView
            review={currentReview}
            agentLiveState={agentLiveState}
            liveFindings={liveFindings}
            showFindings={showFindings}
            onToggleFindings={() => setShowFindings(!showFindings)}
            onCancel={handleCancel}
          />
        )}

        {isComplete && (
          <CompletedView
            review={currentReview}
            projectId={projectId}
            onNewReview={handleNewReview}
          />
        )}

        {loading && !currentReview && (
          <div className="flex items-center justify-center py-6 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <span className="text-sm">Loading reviews...</span>
          </div>
        )}
      </CardContent>
    </Card>
  )
}

// ── Selection View ──

function SelectionView({
  categories,
  selected,
  onToggle,
  onStart,
  starting,
  error,
}: {
  categories: ReviewCategoryInfo[]
  selected: Set<ReviewCategory>
  onToggle: (cat: ReviewCategory) => void
  onStart: () => void
  starting: boolean
  error: string | null
}) {
  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Run multiple AI agents concurrently to perform a comprehensive security assessment.
        Each agent specializes in a different security domain.
      </p>

      <div className="space-y-2">
        {categories.map((cat) => (
          <label
            key={cat.id}
            className="flex items-start gap-3 rounded-md border p-3 cursor-pointer hover:bg-muted/50 transition-colors"
          >
            <Checkbox
              checked={selected.has(cat.id)}
              onCheckedChange={() => onToggle(cat.id)}
              className="mt-0.5"
            />
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium">{cat.label}</span>
                <Badge variant="outline" className="text-[10px] px-1.5 py-0">
                  {cat.modelLabel}
                </Badge>
              </div>
              <p className="text-xs text-muted-foreground mt-0.5">{cat.description}</p>
            </div>
          </label>
        ))}
      </div>

      {error && (
        <div className="flex items-center gap-2 text-sm text-destructive">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      <Button
        onClick={onStart}
        disabled={starting || selected.size === 0}
        className="w-full"
      >
        {starting ? (
          <>
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            Starting Review...
          </>
        ) : (
          <>
            <Play className="mr-2 h-4 w-4" />
            Start Review ({selected.size} agent{selected.size !== 1 ? 's' : ''})
          </>
        )}
      </Button>
    </div>
  )
}

// ── Running View ──

function RunningView({
  review,
  agentLiveState,
  liveFindings,
  showFindings,
  onToggleFindings,
  onCancel,
}: {
  review: SecurityReview
  agentLiveState: Record<string, { currentTool: string | null; toolCallsCount: number; findingsCount: number }>
  liveFindings: { id: string; agentId: string; category: string; title: string; severity: string }[]
  showFindings: boolean
  onToggleFindings: () => void
  onCancel: () => void
}) {
  const totalAgents = review.agents.length
  const completedAgents = review.agents.filter(
    (a) => a.status === 'completed' || a.status === 'failed' || a.status === 'cancelled',
  ).length
  const progress = totalAgents > 0 ? (completedAgents / totalAgents) * 100 : 0

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">
            {completedAgents} / {totalAgents} agents complete
          </span>
          <span className="text-muted-foreground">{Math.round(progress)}%</span>
        </div>
        <Progress value={progress} className="h-2" />
      </div>

      <div className="space-y-1.5">
        {review.agents.map((agent) => (
          <AgentRow
            key={agent.id}
            agent={agent}
            liveState={agentLiveState[agent.id]}
          />
        ))}
      </div>

      {liveFindings.length > 0 && (
        <div>
          <button
            onClick={onToggleFindings}
            className="flex items-center gap-1 text-sm font-medium text-muted-foreground hover:text-foreground transition-colors"
          >
            {showFindings ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
            Live Findings ({liveFindings.length})
          </button>
          {showFindings && (
            <div className="mt-2 space-y-1 max-h-48 overflow-auto">
              {liveFindings.map((f) => (
                <div
                  key={f.id}
                  className="flex items-center gap-2 text-xs rounded border px-2 py-1.5"
                >
                  <SeverityDot severity={f.severity} />
                  <span className="text-muted-foreground shrink-0">
                    {f.category.replace(/_/g, ' ')}:
                  </span>
                  <span className="truncate">{f.title}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      <Button variant="destructive" size="sm" onClick={onCancel} className="w-full">
        <Square className="mr-2 h-3.5 w-3.5" />
        Cancel Review
      </Button>
    </div>
  )
}

// ── Completed View ──

function CompletedView({
  review,
  projectId,
  onNewReview,
}: {
  review: SecurityReview
  projectId: string
  onNewReview: () => void
}) {
  // Count findings by severity across all agents
  const totalFindings = review.agents.reduce((sum, a) => sum + a.findings_count, 0)
  const totalToolCalls = review.agents.reduce((sum, a) => sum + a.tool_calls_count, 0)

  const statusLabel =
    review.status === 'completed' ? 'Completed' :
    review.status === 'cancelled' ? 'Cancelled' :
    'Failed'

  const StatusIcon =
    review.status === 'completed' ? CheckCircle2 :
    review.status === 'cancelled' ? Ban :
    XCircle

  const statusColor =
    review.status === 'completed' ? 'text-green-600' :
    review.status === 'cancelled' ? 'text-yellow-600' :
    'text-destructive'

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <StatusIcon className={`h-5 w-5 ${statusColor}`} />
        <span className={`text-sm font-medium ${statusColor}`}>{statusLabel}</span>
        <span className="text-xs text-muted-foreground ml-auto">
          {totalFindings} finding{totalFindings !== 1 ? 's' : ''} &middot; {totalToolCalls} tool calls
        </span>
      </div>

      <div className="space-y-1.5">
        {review.agents.map((agent) => (
          <div
            key={agent.id}
            className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm"
          >
            <div className="flex items-center gap-2 min-w-0">
              <AgentStatusIcon status={agent.status} />
              <span className="truncate">
                {getCategoryLabel(agent.category)}
              </span>
              {agent.findings_count > 0 && (
                <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
                  {agent.findings_count} finding{agent.findings_count !== 1 ? 's' : ''}
                </Badge>
              )}
            </div>
            {agent.conversation_id && (
              <Button variant="ghost" size="sm" className="h-7 shrink-0" asChild>
                <Link to={`/projects/${projectId}/explore?conversation=${agent.conversation_id}`}>
                  <MessageSquare className="mr-1 h-3.5 w-3.5" />
                  Chat
                </Link>
              </Button>
            )}
          </div>
        ))}
      </div>

      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={onNewReview} className="flex-1">
          <Play className="mr-2 h-3.5 w-3.5" />
          New Review
        </Button>
        <Button variant="outline" size="sm" asChild className="flex-1">
          <Link to={`/projects/${projectId}/findings`}>
            <FileDown className="mr-2 h-3.5 w-3.5" />
            View Findings
          </Link>
        </Button>
      </div>
    </div>
  )
}

// ── Helper Components ──

function AgentRow({
  agent,
  liveState,
}: {
  agent: ReviewAgent
  liveState?: { currentTool: string | null; toolCallsCount: number; findingsCount: number }
}) {
  const toolCalls = liveState?.toolCallsCount ?? agent.tool_calls_count
  const findings = liveState?.findingsCount ?? agent.findings_count
  const currentTool = liveState?.currentTool

  return (
    <div className="flex items-center gap-2 rounded-md border px-3 py-2 text-sm">
      <AgentStatusIcon status={agent.status} />
      <span className="font-medium truncate min-w-0 flex-shrink-0">
        {getCategoryLabel(agent.category)}
      </span>
      <div className="flex-1 min-w-0">
        {agent.status === 'running' && currentTool && (
          <span className="text-xs text-muted-foreground flex items-center gap-1 truncate">
            <Wrench className="h-3 w-3 shrink-0" />
            {currentTool}
          </span>
        )}
        {agent.status === 'failed' && agent.error_message && (
          <span className="text-xs text-destructive truncate">{agent.error_message}</span>
        )}
      </div>
      <div className="flex items-center gap-2 text-xs text-muted-foreground shrink-0">
        {toolCalls > 0 && <span>{toolCalls} calls</span>}
        {findings > 0 && (
          <Badge variant="secondary" className="text-[10px] px-1.5 py-0">
            {findings}
          </Badge>
        )}
      </div>
    </div>
  )
}

function AgentStatusIcon({ status }: { status: AgentStatus }) {
  switch (status) {
    case 'running':
      return <Loader2 className="h-4 w-4 animate-spin text-blue-500 shrink-0" />
    case 'completed':
      return <CheckCircle2 className="h-4 w-4 text-green-600 shrink-0" />
    case 'failed':
      return <XCircle className="h-4 w-4 text-destructive shrink-0" />
    case 'cancelled':
      return <Ban className="h-4 w-4 text-yellow-600 shrink-0" />
    default:
      return <div className="h-4 w-4 rounded-full border-2 border-muted shrink-0" />
  }
}

function SeverityDot({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: 'bg-red-600',
    high: 'bg-orange-500',
    medium: 'bg-yellow-500',
    low: 'bg-blue-500',
    info: 'bg-gray-400',
  }
  return (
    <div className={`h-2 w-2 rounded-full shrink-0 ${colors[severity] ?? 'bg-gray-400'}`} />
  )
}

function getCategoryLabel(category: string): string {
  const info = REVIEW_CATEGORIES.find((c) => c.id === category)
  return info?.label ?? category.replace(/_/g, ' ')
}
