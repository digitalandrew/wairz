import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  ShieldX,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  Info,
  FileText,
  ExternalLink,
  Pencil,
  Check,
  X,
  Trash2,
  Package,
  Bot,
  User,
  Search,
  Bug,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import type { Finding, FindingUpdate, FindingStatus, Severity, FindingSource } from '@/types'
import { formatDate } from '@/utils/format'
import { getCweDescription, getCweMitreUrl } from '@/utils/cwe'

const SEVERITY_CONFIG: Record<Severity, { icon: React.ElementType; className: string; label: string }> = {
  critical: { icon: ShieldX, className: 'bg-red-600 text-white', label: 'Critical' },
  high: { icon: ShieldAlert, className: 'bg-orange-500 text-white', label: 'High' },
  medium: { icon: AlertTriangle, className: 'bg-yellow-500 text-black', label: 'Medium' },
  low: { icon: AlertCircle, className: 'bg-blue-500 text-white', label: 'Low' },
  info: { icon: Info, className: 'bg-gray-500 text-white', label: 'Info' },
}

const STATUS_OPTIONS: { value: FindingStatus; label: string }[] = [
  { value: 'open', label: 'Open' },
  { value: 'confirmed', label: 'Confirmed' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'fixed', label: 'Fixed' },
]

const SOURCE_CONFIG: Record<FindingSource, { icon: React.ElementType; label: string; className: string }> = {
  manual: { icon: User, label: 'Manual', className: 'border-gray-500/50 text-gray-500' },
  ai_discovered: { icon: Bot, label: 'AI Discovered', className: 'border-purple-500/50 text-purple-600 dark:text-purple-400' },
  sbom_scan: { icon: Package, label: 'Inherited Vulnerability', className: 'border-teal-500/50 text-teal-600 dark:text-teal-400' },
  fuzzing: { icon: Bug, label: 'Fuzzing', className: 'border-orange-500/50 text-orange-600 dark:text-orange-400' },
  security_review: { icon: Search, label: 'Security Review', className: 'border-blue-500/50 text-blue-600 dark:text-blue-400' },
}

interface FindingDetailProps {
  finding: Finding
  onUpdate: (findingId: string, updates: FindingUpdate) => Promise<void>
  onDelete: (findingId: string) => Promise<void>
}

export default function FindingDetail({ finding, onUpdate, onDelete }: FindingDetailProps) {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const [editing, setEditing] = useState(false)
  const [editDesc, setEditDesc] = useState(finding.description ?? '')
  const [editEvidence, setEditEvidence] = useState(finding.evidence ?? '')

  const sevConfig = SEVERITY_CONFIG[finding.severity]
  const Icon = sevConfig.icon

  const handleStatusChange = async (status: FindingStatus) => {
    await onUpdate(finding.id, { status })
  }

  const handleSaveEdit = async () => {
    await onUpdate(finding.id, {
      description: editDesc || undefined,
      evidence: editEvidence || undefined,
    })
    setEditing(false)
  }

  const handleCancelEdit = () => {
    setEditDesc(finding.description ?? '')
    setEditEvidence(finding.evidence ?? '')
    setEditing(false)
  }

  const handleNavigateToFile = () => {
    if (finding.file_path && projectId) {
      navigate(`/projects/${projectId}/explore?path=${encodeURIComponent(finding.file_path)}`)
    }
  }

  return (
    <div className="space-y-4 overflow-y-auto">
      {/* Header */}
      <div className="flex items-start gap-3">
        <span className={`mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded ${sevConfig.className}`}>
          <Icon className="h-4 w-4" />
        </span>
        <div className="min-w-0 flex-1">
          <h2 className="text-lg font-semibold leading-tight">{finding.title}</h2>
          <div className="mt-1 flex items-center gap-2 text-sm text-muted-foreground">
            <Badge className={sevConfig.className}>{sevConfig.label}</Badge>
            {finding.source && (() => {
              const srcConfig = SOURCE_CONFIG[finding.source]
              const SrcIcon = srcConfig.icon
              return (
                <Badge variant="outline" className={`text-xs ${srcConfig.className}`}>
                  <SrcIcon className="mr-1 h-3 w-3" />
                  {srcConfig.label}
                </Badge>
              )
            })()}
            <span>{formatDate(finding.created_at)}</span>
          </div>
        </div>
        <div className="flex gap-1">
          {!editing && (
            <Button variant="ghost" size="icon-xs" onClick={() => setEditing(true)} title="Edit">
              <Pencil className="h-4 w-4" />
            </Button>
          )}
          <Button
            variant="ghost"
            size="icon-xs"
            onClick={() => {
              if (window.confirm('Delete this finding?')) onDelete(finding.id)
            }}
            title="Delete"
          >
            <Trash2 className="h-4 w-4 text-destructive" />
          </Button>
        </div>
      </div>

      {/* Status selector */}
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Status:</span>
        {STATUS_OPTIONS.map((opt) => (
          <button
            key={opt.value}
            type="button"
            onClick={() => handleStatusChange(opt.value)}
            className={`rounded-full border px-2.5 py-0.5 text-xs font-medium transition-colors ${
              finding.status === opt.value
                ? 'border-primary bg-primary/10 text-primary'
                : 'border-border text-muted-foreground hover:text-foreground'
            }`}
          >
            {opt.label}
          </button>
        ))}
      </div>

      {/* File path */}
      {finding.file_path && (
        <div className="flex items-center gap-2">
          <FileText className="h-4 w-4 text-muted-foreground" />
          <button
            type="button"
            onClick={handleNavigateToFile}
            className="text-sm font-mono text-primary hover:underline"
          >
            {finding.file_path}
            {finding.line_number != null && `:${finding.line_number}`}
            <ExternalLink className="ml-1 inline h-3 w-3" />
          </button>
        </div>
      )}

      {/* CVEs */}
      {finding.cve_ids && finding.cve_ids.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm text-muted-foreground">CVEs:</span>
          {finding.cve_ids.map((cve) => (
            <Badge key={cve} variant="outline" className="font-mono text-xs">
              {cve}
            </Badge>
          ))}
        </div>
      )}

      {/* CWEs */}
      {finding.cwe_ids && finding.cwe_ids.length > 0 && (
        <div className="flex flex-wrap items-center gap-1.5">
          <span className="text-sm text-muted-foreground">CWEs:</span>
          <TooltipProvider>
            {finding.cwe_ids.map((cwe) => {
              const desc = getCweDescription(cwe)
              const url = getCweMitreUrl(cwe)
              return (
                <Tooltip key={cwe}>
                  <TooltipTrigger asChild>
                    <a
                      href={url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="cursor-pointer"
                    >
                      <Badge variant="outline" className="font-mono text-xs hover:bg-accent">
                        {cwe}
                        <ExternalLink className="ml-1 inline h-2.5 w-2.5" />
                      </Badge>
                    </a>
                  </TooltipTrigger>
                  <TooltipContent side="bottom" className="max-w-72 text-left">
                    <p className="font-semibold">{cwe}</p>
                    <p className="mt-0.5">{desc ?? 'View details on MITRE'}</p>
                  </TooltipContent>
                </Tooltip>
              )
            })}
          </TooltipProvider>
        </div>
      )}

      {/* Description */}
      <div>
        <h3 className="mb-1 text-sm font-medium">Description</h3>
        {editing ? (
          <textarea
            value={editDesc}
            onChange={(e) => setEditDesc(e.target.value)}
            rows={6}
            className="w-full rounded-md border border-input bg-transparent px-3 py-2 text-sm placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          />
        ) : (
          <p className="whitespace-pre-wrap text-sm text-muted-foreground">
            {finding.description || 'No description provided.'}
          </p>
        )}
      </div>

      {/* Evidence */}
      <div>
        <h3 className="mb-1 text-sm font-medium">Evidence</h3>
        {editing ? (
          <textarea
            value={editEvidence}
            onChange={(e) => setEditEvidence(e.target.value)}
            rows={8}
            className="w-full rounded-md border border-input bg-transparent px-3 py-2 font-mono text-xs placeholder:text-muted-foreground focus-visible:border-ring focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-ring"
          />
        ) : finding.evidence ? (
          <pre className="max-h-80 overflow-auto rounded-md bg-muted p-3 text-xs">
            {finding.evidence}
          </pre>
        ) : (
          <p className="text-sm text-muted-foreground">No evidence provided.</p>
        )}
      </div>

      {/* Edit actions */}
      {editing && (
        <div className="flex gap-2">
          <Button size="sm" onClick={handleSaveEdit}>
            <Check className="mr-1 h-3 w-3" /> Save
          </Button>
          <Button size="sm" variant="outline" onClick={handleCancelEdit}>
            <X className="mr-1 h-3 w-3" /> Cancel
          </Button>
        </div>
      )}
    </div>
  )
}
