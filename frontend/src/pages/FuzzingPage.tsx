import { useCallback, useEffect, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Bug,
  Square,
  Loader2,
  RefreshCw,
  AlertCircle,
  AlertTriangle,
  ShieldAlert,
  Search,
  Clock,
  Zap,
  Target,
  BarChart3,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { formatDate } from '@/utils/format'
import {
  analyzeTarget,
  createCampaign,
  startCampaign,
  stopCampaign,
  listCampaigns,
  getCampaign,
  listCrashes,
  triageCrash,
  getCrashDetail,
} from '@/api/fuzzing'
import { createFinding } from '@/api/findings'
import type {
  FuzzingCampaign,
  FuzzingCrash,
  FuzzingStatus,
  FuzzingTargetAnalysis,
  CrashExploitability,
  Severity,
} from '@/types'

const STATUS_CONFIG: Record<FuzzingStatus, { label: string; className: string }> = {
  created: { label: 'Created', className: 'bg-gray-500 text-white' },
  running: { label: 'Running', className: 'bg-green-500 text-white' },
  stopped: { label: 'Stopped', className: 'bg-zinc-600 text-white' },
  completed: { label: 'Completed', className: 'bg-blue-500 text-white' },
  error: { label: 'Error', className: 'bg-red-500 text-white' },
}

const EXPLOIT_CONFIG: Record<CrashExploitability, { label: string; className: string }> = {
  exploitable: { label: 'Exploitable', className: 'bg-red-600 text-white' },
  probably_exploitable: { label: 'Probably Exploitable', className: 'bg-orange-500 text-white' },
  probably_not: { label: 'Probably Not', className: 'bg-yellow-500 text-black' },
  unknown: { label: 'Unknown', className: 'bg-gray-500 text-white' },
}

export default function FuzzingPage() {
  const { projectId } = useParams<{ projectId: string }>()

  const [campaigns, setCampaigns] = useState<FuzzingCampaign[]>([])
  const [loading, setLoading] = useState(true)
  const [creating, setCreating] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // New campaign form
  const [binaryPath, setBinaryPath] = useState('')
  const [timeoutPerExec, setTimeoutPerExec] = useState(1000)
  const [memoryLimit, setMemoryLimit] = useState(256)
  const [analysis, setAnalysis] = useState<FuzzingTargetAnalysis | null>(null)
  const [analyzing, setAnalyzing] = useState(false)

  // Selected campaign
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [crashes, setCrashes] = useState<FuzzingCrash[]>([])
  const [crashesLoading, setCrashesLoading] = useState(false)

  const selectedCampaign = campaigns.find((c) => c.id === selectedId)

  const loadCampaigns = useCallback(async () => {
    if (!projectId) return
    try {
      const data = await listCampaigns(projectId)
      setCampaigns(data)

      // Auto-select running campaign
      const running = data.find((c) => c.status === 'running')
      if (running && !selectedId) {
        setSelectedId(running.id)
      }
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [projectId, selectedId])

  useEffect(() => {
    loadCampaigns()
  }, [loadCampaigns])

  // Poll for updates while a campaign is running
  useEffect(() => {
    if (!projectId) return
    const hasRunning = campaigns.some((c) => c.status === 'running')
    if (!hasRunning) return

    const interval = setInterval(async () => {
      await loadCampaigns()
      // Refresh selected campaign's crashes
      if (selectedId) {
        const running = campaigns.find((c) => c.id === selectedId && c.status === 'running')
        if (running) {
          try {
            const crashData = await listCrashes(projectId, selectedId)
            setCrashes(crashData)
          } catch { /* ignore */ }
        }
      }
    }, 5000)
    return () => clearInterval(interval)
  }, [projectId, campaigns, selectedId, loadCampaigns])

  // Load crashes when selected campaign changes
  useEffect(() => {
    if (!projectId || !selectedId) {
      setCrashes([])
      return
    }
    setCrashesLoading(true)
    listCrashes(projectId, selectedId)
      .then(setCrashes)
      .catch(() => setCrashes([]))
      .finally(() => setCrashesLoading(false))
  }, [projectId, selectedId])

  const handleAnalyze = async () => {
    if (!projectId || !binaryPath.trim()) return
    setAnalyzing(true)
    setAnalysis(null)
    try {
      const result = await analyzeTarget(projectId, binaryPath.trim())
      setAnalysis(result)
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Analysis failed'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const resp = (err as { response?: { data?: { detail?: string } } }).response
        setError(resp?.data?.detail || msg)
      } else {
        setError(msg)
      }
    } finally {
      setAnalyzing(false)
    }
  }

  const handleCreate = async () => {
    if (!projectId || !binaryPath.trim()) return
    setCreating(true)
    setError(null)
    try {
      const campaign = await createCampaign(projectId, {
        binary_path: binaryPath.trim(),
        timeout_per_exec: timeoutPerExec,
        memory_limit: memoryLimit,
      })
      // Auto-start
      const started = await startCampaign(projectId, campaign.id)
      setSelectedId(started.id)
      await loadCampaigns()
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : 'Failed to create campaign'
      if (typeof err === 'object' && err !== null && 'response' in err) {
        const resp = (err as { response?: { data?: { detail?: string } } }).response
        setError(resp?.data?.detail || msg)
      } else {
        setError(msg)
      }
    } finally {
      setCreating(false)
    }
  }

  const handleStop = async (campaignId: string) => {
    if (!projectId) return
    try {
      await stopCampaign(projectId, campaignId)
      await loadCampaigns()
    } catch { /* ignore */ }
  }

  const handleTriage = async (crashId: string) => {
    if (!projectId || !selectedId) return
    try {
      const result = await triageCrash(projectId, selectedId, crashId)
      setCrashes((prev) => prev.map((c) => (c.id === result.id ? result : c)))
    } catch { /* ignore */ }
  }

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
            <h1 className="text-lg font-semibold">Automated Fuzzing</h1>
            <p className="text-sm text-muted-foreground">
              AFL++ QEMU-mode fuzzing for cross-architecture firmware binaries
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={loadCampaigns}>
            <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left panel — controls + campaign list */}
        <div className="w-96 shrink-0 overflow-y-auto border-r border-border p-4 space-y-6">
          {/* New Campaign */}
          <div className="space-y-4">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              New Campaign
            </h2>

            <div>
              <label className="mb-1 block text-xs font-medium text-muted-foreground">
                Binary Path *
              </label>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={binaryPath}
                  onChange={(e) => setBinaryPath(e.target.value)}
                  placeholder="/usr/sbin/httpd"
                  className="flex-1 rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleAnalyze}
                  disabled={analyzing || !binaryPath.trim()}
                >
                  {analyzing ? (
                    <Loader2 className="h-3.5 w-3.5 animate-spin" />
                  ) : (
                    <Search className="h-3.5 w-3.5" />
                  )}
                </Button>
              </div>
            </div>

            {/* Analysis result */}
            {analysis && (
              <TargetAnalysisCard analysis={analysis} />
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Timeout (ms)
                </label>
                <input
                  type="number"
                  value={timeoutPerExec}
                  onChange={(e) => setTimeoutPerExec(parseInt(e.target.value) || 1000)}
                  min={100}
                  max={30000}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
              </div>
              <div>
                <label className="mb-1 block text-xs font-medium text-muted-foreground">
                  Memory (MB)
                </label>
                <input
                  type="number"
                  value={memoryLimit}
                  onChange={(e) => setMemoryLimit(parseInt(e.target.value) || 256)}
                  min={64}
                  max={1024}
                  className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
                />
              </div>
            </div>

            {error && (
              <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
                <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
                {error}
              </div>
            )}

            <Button
              onClick={handleCreate}
              disabled={creating || !binaryPath.trim()}
              className="w-full"
            >
              {creating ? (
                <Loader2 className="mr-1.5 h-4 w-4 animate-spin" />
              ) : (
                <Bug className="mr-1.5 h-4 w-4" />
              )}
              {creating ? 'Starting...' : 'Create & Start Campaign'}
            </Button>
          </div>

          {/* Campaign list */}
          <div className="space-y-3">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Campaigns ({campaigns.length})
            </h2>

            {campaigns.length === 0 && (
              <p className="text-xs text-muted-foreground/60">No fuzzing campaigns yet</p>
            )}

            {campaigns.map((campaign) => (
              <CampaignCard
                key={campaign.id}
                campaign={campaign}
                isSelected={selectedId === campaign.id}
                onSelect={() => setSelectedId(campaign.id)}
                onStop={() => handleStop(campaign.id)}
              />
            ))}
          </div>
        </div>

        {/* Right panel — stats + crashes */}
        <div className="flex-1 overflow-y-auto p-6">
          {selectedCampaign ? (
            <CampaignDetail
              projectId={projectId!}
              campaign={selectedCampaign}
              crashes={crashes}
              crashesLoading={crashesLoading}
              onTriage={handleTriage}
              onCrashUpdate={(updated) =>
                setCrashes((prev) => prev.map((c) => (c.id === updated.id ? updated : c)))
              }
              onRefresh={async () => {
                if (!projectId || !selectedId) return
                try {
                  const updated = await getCampaign(projectId, selectedId)
                  setCampaigns((prev) => prev.map((c) => (c.id === updated.id ? updated : c)))
                  const crashData = await listCrashes(projectId, selectedId)
                  setCrashes(crashData)
                } catch { /* ignore */ }
              }}
            />
          ) : (
            <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
              <div className="text-center">
                <Bug className="mx-auto mb-3 h-10 w-10 text-muted-foreground/30" />
                <p>Select a campaign or start a new one</p>
                <p className="mt-1 text-xs text-muted-foreground/60">
                  Campaign stats and crash details will appear here
                </p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Target Analysis Card ──

function TargetAnalysisCard({ analysis }: { analysis: FuzzingTargetAnalysis }) {
  const score = analysis.fuzzing_score
  const scoreColor =
    score >= 60 ? 'text-green-500' : score >= 30 ? 'text-yellow-500' : 'text-red-500'

  return (
    <div className="rounded-lg border border-border p-3 space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-medium text-muted-foreground">Fuzzing Score</span>
        <span className={`text-lg font-bold ${scoreColor}`}>{score}/100</span>
      </div>

      <div className="h-1.5 rounded-full bg-muted">
        <div
          className={`h-full rounded-full ${
            score >= 60 ? 'bg-green-500' : score >= 30 ? 'bg-yellow-500' : 'bg-red-500'
          }`}
          style={{ width: `${score}%` }}
        />
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div>
          <span className="text-muted-foreground">Strategy: </span>
          <span className="font-medium">{analysis.recommended_strategy}</span>
        </div>
        <div>
          <span className="text-muted-foreground">Functions: </span>
          <span className="font-medium">{analysis.function_count}</span>
        </div>
      </div>

      {analysis.dangerous_functions.length > 0 && (
        <div className="text-xs">
          <span className="text-muted-foreground">Dangerous sinks: </span>
          <span className="font-mono text-orange-500">
            {analysis.dangerous_functions.join(', ')}
          </span>
        </div>
      )}

      {analysis.input_sources.length > 0 && (
        <div className="text-xs">
          <span className="text-muted-foreground">Input functions: </span>
          <span className="font-mono">{analysis.input_sources.join(', ')}</span>
        </div>
      )}
    </div>
  )
}

// ── Campaign Card ──

function CampaignCard({
  campaign,
  isSelected,
  onSelect,
  onStop,
}: {
  campaign: FuzzingCampaign
  isSelected: boolean
  onSelect: () => void
  onStop: () => void
}) {
  const statusCfg = STATUS_CONFIG[campaign.status] || STATUS_CONFIG.created

  return (
    <div
      className={`cursor-pointer rounded-lg border p-3 transition-colors ${
        isSelected
          ? 'border-primary/50 bg-primary/5'
          : 'border-border hover:border-border/80'
      }`}
      onClick={onSelect}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Badge className={`text-[10px] ${statusCfg.className}`}>
            {statusCfg.label}
          </Badge>
          {campaign.crashes_count > 0 && (
            <Badge className="bg-red-500/10 text-red-500 text-[10px] border-red-500/30">
              {campaign.crashes_count} crash{campaign.crashes_count !== 1 ? 'es' : ''}
            </Badge>
          )}
        </div>
        {campaign.status === 'running' && (
          <Button
            variant="destructive"
            size="sm"
            className="h-6 text-[10px] px-2"
            onClick={(e) => {
              e.stopPropagation()
              onStop()
            }}
          >
            <Square className="mr-1 h-2.5 w-2.5" />
            Stop
          </Button>
        )}
      </div>

      <p className="mt-1 truncate text-xs text-muted-foreground font-mono">
        {campaign.binary_path}
      </p>

      <div className="mt-1 flex items-center gap-3 text-[10px] text-muted-foreground">
        <span className="flex items-center gap-1">
          <Clock className="h-3 w-3" />
          {formatDate(campaign.created_at)}
        </span>
        {campaign.stats && (
          <span className="flex items-center gap-1">
            <Zap className="h-3 w-3" />
            {typeof campaign.stats.execs_per_sec === 'number'
              ? `${campaign.stats.execs_per_sec.toFixed(1)}/s`
              : '—'}
          </span>
        )}
      </div>

      {campaign.error_message && (
        <div className="mt-2 rounded-md bg-destructive/10 px-2 py-1 text-[10px] text-destructive">
          <AlertCircle className="mr-1 inline h-3 w-3" />
          {campaign.error_message.slice(0, 100)}
        </div>
      )}
    </div>
  )
}

// ── Campaign Detail ──

function CampaignDetail({
  projectId,
  campaign,
  crashes,
  crashesLoading,
  onTriage,
  onRefresh,
  onCrashUpdate,
}: {
  projectId: string
  campaign: FuzzingCampaign
  crashes: FuzzingCrash[]
  crashesLoading: boolean
  onTriage: (crashId: string) => void
  onRefresh: () => void
  onCrashUpdate: (crash: FuzzingCrash) => void
}) {
  const stats = campaign.stats
  const [expandedCrash, setExpandedCrash] = useState<string | null>(null)
  const [hexDumps, setHexDumps] = useState<Record<string, string | null>>({})
  const [hexLoading, setHexLoading] = useState<Record<string, boolean>>({})
  const [findingCreating, setFindingCreating] = useState<Record<string, boolean>>({})

  const loadHexDump = async (crashId: string) => {
    if (hexDumps[crashId] !== undefined) return
    setHexLoading((prev) => ({ ...prev, [crashId]: true }))
    try {
      const detail = await getCrashDetail(projectId, campaign.id, crashId)
      setHexDumps((prev) => ({ ...prev, [crashId]: detail.crash_input_hex }))
    } catch {
      setHexDumps((prev) => ({ ...prev, [crashId]: null }))
    } finally {
      setHexLoading((prev) => ({ ...prev, [crashId]: false }))
    }
  }

  const handleCreateFinding = async (crash: FuzzingCrash) => {
    setFindingCreating((prev) => ({ ...prev, [crash.id]: true }))
    try {
      const finding = await createFinding(projectId, {
        title: `Fuzzing crash: ${crash.signal || 'unknown signal'} in ${campaign.binary_path}`,
        severity: exploitabilityToSeverity(crash.exploitability),
        description: [
          `AFL++ fuzzing discovered a crash in \`${campaign.binary_path}\`.`,
          '',
          `- **Crash file:** ${crash.crash_filename}`,
          `- **Signal:** ${crash.signal || 'unknown'}`,
          `- **Exploitability:** ${crash.exploitability || 'not triaged'}`,
          crash.crash_size != null ? `- **Input size:** ${crash.crash_size} bytes` : '',
        ].filter(Boolean).join('\n'),
        evidence: crash.triage_output || crash.stack_trace || undefined,
        file_path: campaign.binary_path,
        source: 'fuzzing',
      })
      onCrashUpdate({ ...crash, finding_id: finding.id })
    } catch {
      // ignore
    } finally {
      setFindingCreating((prev) => ({ ...prev, [crash.id]: false }))
    }
  }

  return (
    <div className="space-y-6">
      {/* Campaign header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-2">
            <h2 className="text-base font-semibold">Campaign Details</h2>
            <Badge className={`text-[10px] ${STATUS_CONFIG[campaign.status]?.className}`}>
              {campaign.status}
            </Badge>
          </div>
          <p className="mt-0.5 text-sm font-mono text-muted-foreground">{campaign.binary_path}</p>
        </div>
        <Button variant="outline" size="sm" onClick={onRefresh}>
          <RefreshCw className="mr-1.5 h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {/* Stats grid */}
      {stats && (
        <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
          <StatCard
            icon={Zap}
            label="Execs/sec"
            value={typeof stats.execs_per_sec === 'number' ? stats.execs_per_sec.toFixed(1) : '—'}
          />
          <StatCard
            icon={BarChart3}
            label="Total Execs"
            value={typeof stats.total_execs === 'number' ? stats.total_execs.toLocaleString() : '—'}
          />
          <StatCard
            icon={Target}
            label="Corpus"
            value={String(stats.corpus_count ?? 0)}
          />
          <StatCard
            icon={ShieldAlert}
            label="Crashes"
            value={String(stats.saved_crashes ?? 0)}
            alert={(stats.saved_crashes ?? 0) > 0}
          />
          <StatCard
            icon={AlertTriangle}
            label="Hangs"
            value={String(stats.saved_hangs ?? 0)}
          />
          <StatCard
            label="Stability"
            value={String(stats.stability ?? '—')}
          />
          <StatCard
            label="Coverage"
            value={String(stats.bitmap_cvg ?? '—')}
          />
          <StatCard
            icon={Clock}
            label="Run Time"
            value={formatDuration(Number(stats.run_time ?? 0))}
          />
        </div>
      )}

      {!stats && campaign.status === 'running' && (
        <div className="flex items-center gap-2 py-4 text-sm text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          Waiting for AFL++ stats...
        </div>
      )}

      {/* Crashes */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
          Crashes ({crashes.length})
        </h3>

        {crashesLoading && (
          <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            Loading crashes...
          </div>
        )}

        {!crashesLoading && crashes.length === 0 && (
          <p className="py-4 text-center text-xs text-muted-foreground/60">
            {campaign.status === 'running'
              ? 'No crashes found yet — fuzzer is running...'
              : 'No crashes found for this campaign'}
          </p>
        )}

        {crashes.map((crash) => {
          const isExpanded = expandedCrash === crash.id
          const exploitCfg = crash.exploitability
            ? EXPLOIT_CONFIG[crash.exploitability]
            : null

          return (
            <div key={crash.id} className="rounded-lg border border-border">
              <button
                onClick={() => {
                  const next = isExpanded ? null : crash.id
                  setExpandedCrash(next)
                  if (next) loadHexDump(crash.id)
                }}
                className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-accent/50 transition-colors"
              >
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-mono font-medium">{crash.crash_filename}</span>
                    {crash.signal && (
                      <Badge variant="outline" className="text-[10px]">{crash.signal}</Badge>
                    )}
                    {exploitCfg && (
                      <Badge className={`text-[10px] ${exploitCfg.className}`}>
                        {exploitCfg.label}
                      </Badge>
                    )}
                    {crash.crash_size != null && (
                      <span className="text-[10px] text-muted-foreground">
                        {crash.crash_size} bytes
                      </span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {!crash.triage_output && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-6 text-[10px] px-2"
                      onClick={(e) => {
                        e.stopPropagation()
                        onTriage(crash.id)
                      }}
                    >
                      Triage
                    </Button>
                  )}
                  {isExpanded ? (
                    <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" />
                  ) : (
                    <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                  )}
                </div>
              </button>

              {isExpanded && (
                <div className="border-t border-border bg-muted/30 px-4 py-3 space-y-3">
                  {crash.stack_trace && (
                    <div>
                      <p className="mb-1 text-xs font-medium text-muted-foreground">Stack Trace</p>
                      <pre className="max-h-40 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {crash.stack_trace}
                      </pre>
                    </div>
                  )}
                  {crash.triage_output && !crash.stack_trace && (
                    <div>
                      <p className="mb-1 text-xs font-medium text-muted-foreground">Triage Output</p>
                      <pre className="max-h-60 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {crash.triage_output}
                      </pre>
                    </div>
                  )}

                  {/* Hex dump of crash input */}
                  <div>
                    <p className="mb-1 text-xs font-medium text-muted-foreground">Crash Input</p>
                    {hexLoading[crash.id] ? (
                      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
                        <Loader2 className="h-3 w-3 animate-spin" />
                        Loading crash input...
                      </div>
                    ) : hexDumps[crash.id] ? (
                      <pre className="max-h-48 overflow-auto rounded-md bg-[#0a0a0b] p-2 text-[11px] text-zinc-300 font-mono">
                        {formatHexDump(hexDumps[crash.id]!)}
                      </pre>
                    ) : hexDumps[crash.id] === null ? (
                      <p className="text-xs text-muted-foreground/60">Crash input not available</p>
                    ) : null}
                  </div>

                  {/* Create finding button */}
                  {crash.triage_output && !crash.finding_id && (
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      disabled={findingCreating[crash.id]}
                      onClick={() => handleCreateFinding(crash)}
                    >
                      {findingCreating[crash.id] ? (
                        <Loader2 className="mr-1.5 h-3 w-3 animate-spin" />
                      ) : (
                        <ShieldAlert className="mr-1.5 h-3 w-3" />
                      )}
                      Create Finding
                    </Button>
                  )}
                  {crash.finding_id && (
                    <div className="flex items-center gap-1.5 text-xs text-green-500">
                      <ShieldAlert className="h-3 w-3" />
                      Finding created
                    </div>
                  )}

                  {!crash.triage_output && !crash.finding_id && (
                    <p className="text-xs text-muted-foreground">
                      Click "Triage" to reproduce this crash and analyze exploitability.
                    </p>
                  )}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ── Helper components ──

function StatCard({
  icon: Icon,
  label,
  value,
  alert,
}: {
  icon?: React.ElementType
  label: string
  value: string
  alert?: boolean
}) {
  return (
    <div className={`rounded-lg border p-3 ${alert ? 'border-red-500/30 bg-red-500/5' : 'border-border'}`}>
      <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
        {Icon && <Icon className="h-3 w-3" />}
        {label}
      </div>
      <p className={`mt-1 text-lg font-bold ${alert ? 'text-red-500' : ''}`}>{value}</p>
    </div>
  )
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ${seconds % 60}s`
  const h = Math.floor(seconds / 3600)
  const m = Math.floor((seconds % 3600) / 60)
  return `${h}h ${m}m`
}

function formatHexDump(hex: string): string {
  const bytes: number[] = []
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16))
  }
  const lines: string[] = []
  for (let offset = 0; offset < bytes.length; offset += 16) {
    const chunk = bytes.slice(offset, offset + 16)
    const addr = offset.toString(16).padStart(8, '0')
    const hexPart = chunk.map((b) => b.toString(16).padStart(2, '0')).join(' ')
    const ascii = chunk
      .map((b) => (b >= 0x20 && b <= 0x7e ? String.fromCharCode(b) : '.'))
      .join('')
    lines.push(`${addr}  ${hexPart.padEnd(48)}  |${ascii}|`)
  }
  return lines.join('\n')
}

function exploitabilityToSeverity(e: CrashExploitability | null): Severity {
  switch (e) {
    case 'exploitable': return 'critical'
    case 'probably_exploitable': return 'high'
    case 'probably_not': return 'medium'
    default: return 'medium'
  }
}
