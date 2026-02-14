import { useState, useMemo } from 'react'
import {
  AlertTriangle,
  AlertCircle,
  Info,
  ShieldAlert,
  ShieldX,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import type { Finding, Severity, FindingStatus } from '@/types'
import { formatDate } from '@/utils/format'

const SEVERITY_CONFIG: Record<Severity, { icon: React.ElementType; className: string; order: number }> = {
  critical: { icon: ShieldX, className: 'bg-red-600 text-white', order: 0 },
  high: { icon: ShieldAlert, className: 'bg-orange-500 text-white', order: 1 },
  medium: { icon: AlertTriangle, className: 'bg-yellow-500 text-black', order: 2 },
  low: { icon: AlertCircle, className: 'bg-blue-500 text-white', order: 3 },
  info: { icon: Info, className: 'bg-gray-500 text-white', order: 4 },
}

const STATUS_CONFIG: Record<FindingStatus, { label: string; className: string }> = {
  open: { label: 'Open', className: 'border-yellow-500/50 text-yellow-600 dark:text-yellow-400' },
  confirmed: { label: 'Confirmed', className: 'border-red-500/50 text-red-600 dark:text-red-400' },
  false_positive: { label: 'False Positive', className: 'border-gray-500/50 text-gray-500' },
  fixed: { label: 'Fixed', className: 'border-green-500/50 text-green-600 dark:text-green-400' },
}

interface FindingsListProps {
  findings: Finding[]
  selectedId: string | null
  onSelect: (finding: Finding) => void
  severityFilter: Severity | null
  statusFilter: FindingStatus | null
  onSeverityFilter: (s: Severity | null) => void
  onStatusFilter: (s: FindingStatus | null) => void
}

type SortField = 'severity' | 'created_at'
type SortDir = 'asc' | 'desc'

export default function FindingsList({
  findings,
  selectedId,
  onSelect,
  severityFilter,
  statusFilter,
  onSeverityFilter,
  onStatusFilter,
}: FindingsListProps) {
  const [sortField, setSortField] = useState<SortField>('severity')
  const [sortDir, setSortDir] = useState<SortDir>('asc')

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDir((d) => (d === 'asc' ? 'desc' : 'asc'))
    } else {
      setSortField(field)
      setSortDir('asc')
    }
  }

  const sorted = useMemo(() => {
    return [...findings].sort((a, b) => {
      let cmp: number
      if (sortField === 'severity') {
        cmp = SEVERITY_CONFIG[a.severity].order - SEVERITY_CONFIG[b.severity].order
      } else {
        cmp = new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  }, [findings, sortField, sortDir])

  const SortIcon = sortField === 'severity'
    ? (sortDir === 'asc' ? ChevronUp : ChevronDown)
    : (sortDir === 'asc' ? ChevronUp : ChevronDown)

  return (
    <div className="flex flex-col gap-3">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Severity:</span>
        {(['critical', 'high', 'medium', 'low', 'info'] as Severity[]).map((sev) => {
          const config = SEVERITY_CONFIG[sev]
          const active = severityFilter === sev
          return (
            <button
              key={sev}
              type="button"
              onClick={() => onSeverityFilter(active ? null : sev)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.className
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {sev}
            </button>
          )
        })}

        <span className="ml-2 text-xs text-muted-foreground">Status:</span>
        {(['open', 'confirmed', 'false_positive', 'fixed'] as FindingStatus[]).map((st) => {
          const config = STATUS_CONFIG[st]
          const active = statusFilter === st
          return (
            <button
              key={st}
              type="button"
              onClick={() => onStatusFilter(active ? null : st)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.className + ' border-current'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {config.label}
            </button>
          )
        })}
      </div>

      {/* Sort controls */}
      <div className="flex items-center gap-2 text-xs text-muted-foreground">
        <span>Sort by:</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => toggleSort('severity')}
        >
          Severity
          {sortField === 'severity' && <SortIcon className="ml-1 h-3 w-3" />}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          className="h-6 px-2 text-xs"
          onClick={() => toggleSort('created_at')}
        >
          Date
          {sortField === 'created_at' && <SortIcon className="ml-1 h-3 w-3" />}
        </Button>
        <span className="ml-auto">{findings.length} finding(s)</span>
      </div>

      {/* List */}
      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <ShieldAlert className="mb-2 h-8 w-8" />
          <p className="text-sm">No findings yet</p>
          <p className="text-xs">Use the AI assistant to analyze firmware and record findings</p>
        </div>
      ) : (
        <div className="space-y-1">
          {sorted.map((f) => {
            const sevConfig = SEVERITY_CONFIG[f.severity]
            const statConfig = STATUS_CONFIG[f.status]
            const Icon = sevConfig.icon
            const isSelected = selectedId === f.id

            return (
              <button
                key={f.id}
                type="button"
                onClick={() => onSelect(f)}
                className={`flex w-full items-start gap-3 rounded-md border px-3 py-2.5 text-left transition-colors ${
                  isSelected
                    ? 'border-primary/50 bg-primary/5'
                    : 'border-transparent hover:bg-accent'
                }`}
              >
                <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded ${sevConfig.className}`}>
                  <Icon className="h-3 w-3" />
                </span>
                <div className="min-w-0 flex-1">
                  <div className="flex items-center gap-2">
                    <span className="truncate text-sm font-medium">{f.title}</span>
                    <Badge variant="outline" className={`shrink-0 text-[10px] ${statConfig.className}`}>
                      {statConfig.label}
                    </Badge>
                  </div>
                  <div className="mt-0.5 flex items-center gap-2 text-xs text-muted-foreground">
                    {f.file_path && (
                      <span className="truncate font-mono">{f.file_path}</span>
                    )}
                    <span className="shrink-0">{formatDate(f.created_at)}</span>
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      )}
    </div>
  )
}
