import { useCallback, useEffect, useMemo, useState } from 'react'
import { useParams } from 'react-router-dom'
import {
  Package,
  ShieldAlert,
  AlertTriangle,
  AlertCircle,
  ShieldX,
  Info,
  Loader2,
  RefreshCw,
  Download,
  Search,
  ExternalLink,
  ChevronDown,
  ChevronRight,
  Bot,
  MoreHorizontal,
  X,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from '@/components/ui/tooltip'
import { formatDate } from '@/utils/format'
import {
  generateSbom,
  getSbomComponents,
  exportSbom,
  runVulnerabilityScan,
  getVulnerabilities,
  getVulnerabilitySummary,
  updateVulnerability,
} from '@/api/sbom'
import type {
  SbomComponent,
  SbomVulnerability,
  SbomSummary,
  Severity,
  VulnerabilityResolutionStatus,
  VulnerabilityScanResult,
} from '@/types'

// ── Severity display config ──

const SEVERITY_CONFIG: Record<Severity, { icon: React.ElementType; className: string; bg: string }> = {
  critical: { icon: ShieldX, className: 'text-red-600', bg: 'bg-red-600 text-white' },
  high: { icon: ShieldAlert, className: 'text-orange-500', bg: 'bg-orange-500 text-white' },
  medium: { icon: AlertTriangle, className: 'text-yellow-500', bg: 'bg-yellow-500 text-black' },
  low: { icon: AlertCircle, className: 'text-blue-500', bg: 'bg-blue-500 text-white' },
  info: { icon: Info, className: 'text-gray-500', bg: 'bg-gray-500 text-white' },
}

const CONFIDENCE_STYLE: Record<string, string> = {
  high: 'border-green-500/50 text-green-600 dark:text-green-400',
  medium: 'border-yellow-500/50 text-yellow-600 dark:text-yellow-400',
  low: 'border-orange-500/50 text-orange-600 dark:text-orange-400',
}

const CONFIDENCE_DESCRIPTION: Record<string, string> = {
  high: 'High confidence — identified from package manager database, ELF SONAME, or kernel module directory',
  medium: 'Medium confidence — identified from version strings found in the binary',
  low: 'Low confidence — identified from config files or heuristic matching',
}

const RESOLUTION_CONFIG: Record<VulnerabilityResolutionStatus, { label: string; className: string }> = {
  open: { label: 'Open', className: 'bg-blue-500/10 text-blue-500 border-blue-500/30' },
  resolved: { label: 'Resolved', className: 'bg-green-500/10 text-green-500 border-green-500/30' },
  ignored: { label: 'Ignored', className: 'bg-gray-500/10 text-gray-400 border-gray-500/30' },
  false_positive: { label: 'False Positive', className: 'bg-purple-500/10 text-purple-500 border-purple-500/30' },
}

type ResolutionFilter = VulnerabilityResolutionStatus | 'all'

type Tab = 'components' | 'vulnerabilities'

export default function SbomPage() {
  const { projectId } = useParams<{ projectId: string }>()


  const [tab, setTab] = useState<Tab>('components')
  const [components, setComponents] = useState<SbomComponent[]>([])
  const [vulnerabilities, setVulnerabilities] = useState<SbomVulnerability[]>([])
  const [summary, setSummary] = useState<SbomSummary | null>(null)
  const [loading, setLoading] = useState(true)
  const [generating, setGenerating] = useState(false)
  const [scanning, setScanning] = useState(false)
  const [scanResult, setScanResult] = useState<VulnerabilityScanResult | null>(null)
  const [typeFilter, setTypeFilter] = useState<string | null>(null)
  const [nameSearch, setNameSearch] = useState('')
  const [sevFilter, setSevFilter] = useState<string | null>(null)
  const [resolutionFilter, setResolutionFilter] = useState<ResolutionFilter>('open')
  const [expandedComp, setExpandedComp] = useState<string | null>(null)
  const [actionMenuId, setActionMenuId] = useState<string | null>(null)
  const [justificationDialog, setJustificationDialog] = useState<{
    vulnId: string
    status: VulnerabilityResolutionStatus
  } | null>(null)
  const [justificationText, setJustificationText] = useState('')

  // Load data on mount
  const loadData = useCallback(async () => {
    if (!projectId) return
    setLoading(true)
    try {
      const [comps, summary] = await Promise.all([
        getSbomComponents(projectId).catch(() => []),
        getVulnerabilitySummary(projectId).catch(() => null),
      ])
      setComponents(comps)
      setSummary(summary)

      if (summary && summary.total_vulnerabilities > 0) {
        const filters: { resolution_status?: string } = {}
        if (resolutionFilter !== 'all') {
          filters.resolution_status = resolutionFilter
        }
        const vulns = await getVulnerabilities(projectId, filters).catch(() => [])
        setVulnerabilities(vulns)
      }
    } finally {
      setLoading(false)
    }
  }, [projectId, resolutionFilter])

  useEffect(() => {
    loadData()
  }, [loadData])

  // Reload vulns when resolution filter changes (without full reload)
  const reloadVulns = useCallback(async () => {
    if (!projectId) return
    const filters: { resolution_status?: string } = {}
    if (resolutionFilter !== 'all') {
      filters.resolution_status = resolutionFilter
    }
    const vulns = await getVulnerabilities(projectId, filters).catch(() => [])
    setVulnerabilities(vulns)
    const s = await getVulnerabilitySummary(projectId).catch(() => null)
    setSummary(s)
  }, [projectId, resolutionFilter])

  // Handle resolution status update
  const handleResolve = useCallback(async (vulnId: string, status: VulnerabilityResolutionStatus, justification?: string) => {
    if (!projectId) return
    try {
      await updateVulnerability(projectId, vulnId, {
        resolution_status: status,
        resolution_justification: justification,
      })
      await reloadVulns()
    } catch (err) {
      console.error('Failed to update vulnerability:', err)
    }
    setActionMenuId(null)
    setJustificationDialog(null)
    setJustificationText('')
  }, [projectId, reloadVulns])

  // Generate SBOM
  const handleGenerate = useCallback(async (force = false) => {
    if (!projectId) return
    setGenerating(true)
    try {
      const result = await generateSbom(projectId, force)
      setComponents(result.components)
      // Reload summary
      const s = await getVulnerabilitySummary(projectId).catch(() => null)
      setSummary(s)
    } catch (err) {
      console.error('SBOM generation failed:', err)
    } finally {
      setGenerating(false)
    }
  }, [projectId])

  // Run vulnerability scan
  const handleScan = useCallback(async (force = false) => {
    if (!projectId) return
    setScanning(true)
    setScanResult(null)
    try {
      const result = await runVulnerabilityScan(projectId, force)
      setScanResult(result)
      // Reload data
      const [vulns, comps, s] = await Promise.all([
        getVulnerabilities(projectId),
        getSbomComponents(projectId),
        getVulnerabilitySummary(projectId),
      ])
      setVulnerabilities(vulns)
      setComponents(comps)
      setSummary(s)
    } catch (err) {
      console.error('Vulnerability scan failed:', err)
    } finally {
      setScanning(false)
    }
  }, [projectId])

  // Export SBOM
  const handleExport = useCallback(async () => {
    if (!projectId) return
    try {
      const blob = await exportSbom(projectId)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `sbom-${projectId}.cdx.json`
      a.click()
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('SBOM export failed:', err)
    }
  }, [projectId])

  // Filter components
  const filteredComponents = components.filter((c) => {
    if (typeFilter && c.type !== typeFilter) return false
    if (nameSearch && !c.name.toLowerCase().includes(nameSearch.toLowerCase())) return false
    return true
  })

  // Filter vulnerabilities
  const filteredVulns = vulnerabilities.filter((v) => {
    if (sevFilter && v.severity !== sevFilter) return false
    return true
  })

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading SBOM data...</span>
      </div>
    )
  }

  const hasComponents = components.length > 0
  const hasVulns = vulnerabilities.length > 0

  return (
    <div className="mx-auto max-w-6xl space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Package className="h-6 w-6 text-muted-foreground" />
          <div>
            <h1 className="text-lg font-semibold">Software Bill of Materials</h1>
            <p className="text-sm text-muted-foreground">
              {hasComponents
                ? `${components.length} components identified`
                : 'Generate an SBOM to identify firmware components'}
              {summary?.scan_date && ` \u00b7 Last scanned ${formatDate(summary.scan_date)}`}
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {hasComponents && (
            <>
              <Button variant="outline" size="sm" onClick={handleExport}>
                <Download className="mr-1.5 h-3.5 w-3.5" />
                Export
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => handleGenerate(true)}
                disabled={generating}
              >
                {generating ? <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" /> : <RefreshCw className="mr-1.5 h-3.5 w-3.5" />}
                Regenerate
              </Button>
            </>
          )}
          {!hasComponents && (
            <Button onClick={() => handleGenerate(false)} disabled={generating}>
              {generating ? <Loader2 className="mr-1.5 h-4 w-4 animate-spin" /> : <Package className="mr-1.5 h-4 w-4" />}
              Generate SBOM
            </Button>
          )}
        </div>
      </div>

      {/* Summary cards */}
      {summary && summary.total_components > 0 && (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <SummaryCard
            label="Components"
            value={summary.total_components}
            detail={Object.entries(summary.components_by_type).map(
              ([k, v]) => `${v} ${k}`
            ).join(', ')}
          />
          <SummaryCard
            label="Vulnerabilities"
            value={summary.total_vulnerabilities}
            detail={summary.total_vulnerabilities > 0 ? `${summary.components_with_vulns} affected components` : 'No scan results yet'}
            alert={summary.total_vulnerabilities > 0}
          />
          <SummaryCard
            label="Critical / High"
            value={(summary.vulns_by_severity['critical'] ?? 0) + (summary.vulns_by_severity['high'] ?? 0)}
            detail={`${summary.vulns_by_severity['critical'] ?? 0} critical, ${summary.vulns_by_severity['high'] ?? 0} high`}
            alert={((summary.vulns_by_severity['critical'] ?? 0) + (summary.vulns_by_severity['high'] ?? 0)) > 0}
          />
          <SummaryCard
            label="Open / Resolved"
            value={summary.open_count}
            detail={`${summary.open_count} open, ${summary.resolved_count} resolved`}
            alert={summary.open_count > 0}
          />
        </div>
      )}

      {/* Scan button */}
      {hasComponents && (
        <div className="flex items-center gap-3">
          <Button
            onClick={() => handleScan(hasVulns)}
            disabled={scanning}
            variant={hasVulns ? 'outline' : 'default'}
            size="sm"
          >
            {scanning ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <ShieldAlert className="mr-1.5 h-3.5 w-3.5" />
            )}
            {scanning ? 'Scanning NVD...' : hasVulns ? 'Rescan Vulnerabilities' : 'Scan for Vulnerabilities'}
          </Button>
          {scanning && (
            <span className="text-xs text-muted-foreground">
              Querying NVD for each component — this may take 30-60 seconds...
            </span>
          )}
          {scanResult && !scanning && (
            <span className="text-xs text-muted-foreground">
              Found {scanResult.total_vulnerabilities_found} CVEs across {scanResult.total_components_scanned} components
              {scanResult.findings_created > 0 && ` \u00b7 ${scanResult.findings_created} findings created`}
            </span>
          )}
        </div>
      )}

      {/* Tabs */}
      {hasComponents && (
        <>
          <div className="flex gap-1 border-b border-border">
            <TabButton
              active={tab === 'components'}
              onClick={() => setTab('components')}
              label="Components"
              count={components.length}
            />
            <TabButton
              active={tab === 'vulnerabilities'}
              onClick={() => setTab('vulnerabilities')}
              label="Vulnerabilities"
              count={vulnerabilities.length}
              alert={vulnerabilities.length > 0}
            />
          </div>

          {tab === 'components' && (
            <ComponentsTab
              components={filteredComponents}
              typeFilter={typeFilter}
              nameSearch={nameSearch}
              onTypeFilter={setTypeFilter}
              onNameSearch={setNameSearch}
              expandedComp={expandedComp}
              onToggleExpand={(id) => setExpandedComp(prev => prev === id ? null : id)}
              allTypes={[...new Set(components.map((c) => c.type))]}
            />
          )}

          {tab === 'vulnerabilities' && (
            <VulnerabilitiesTab
              vulnerabilities={filteredVulns}
              sevFilter={sevFilter}
              onSevFilter={setSevFilter}
              resolutionFilter={resolutionFilter}
              onResolutionFilter={setResolutionFilter}
              actionMenuId={actionMenuId}
              onActionMenu={setActionMenuId}
              onResolve={handleResolve}
              justificationDialog={justificationDialog}
              onJustificationDialog={setJustificationDialog}
              justificationText={justificationText}
              onJustificationText={setJustificationText}
            />
          )}
        </>
      )}
    </div>
  )
}

// ── Sub-components ──

function SummaryCard({ label, value, detail, alert }: {
  label: string
  value: number
  detail: string
  alert?: boolean
}) {
  return (
    <div className={`rounded-lg border p-4 ${alert ? 'border-red-500/30 bg-red-500/5' : 'border-border'}`}>
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className={`text-2xl font-bold ${alert ? 'text-red-500' : ''}`}>{value}</p>
      <p className="mt-1 text-xs text-muted-foreground">{detail}</p>
    </div>
  )
}

function TabButton({ active, onClick, label, count, alert }: {
  active: boolean
  onClick: () => void
  label: string
  count: number
  alert?: boolean
}) {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
        active
          ? 'border-primary text-foreground'
          : 'border-transparent text-muted-foreground hover:text-foreground'
      }`}
    >
      {label}
      {count > 0 && (
        <span className={`ml-1.5 rounded-full px-1.5 py-0.5 text-xs ${
          alert ? 'bg-red-500/10 text-red-500' : 'bg-muted text-muted-foreground'
        }`}>
          {count}
        </span>
      )}
    </button>
  )
}

// ── Components Tab ──

function ComponentsTab({ components, typeFilter, nameSearch, onTypeFilter, onNameSearch, expandedComp, onToggleExpand, allTypes }: {
  components: SbomComponent[]
  typeFilter: string | null
  nameSearch: string
  onTypeFilter: (t: string | null) => void
  onNameSearch: (s: string) => void
  expandedComp: string | null
  onToggleExpand: (id: string) => void
  allTypes: string[]
}) {
  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="relative">
          <Search className="absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search components..."
            value={nameSearch}
            onChange={(e) => onNameSearch(e.target.value)}
            className="h-8 rounded-md border border-input bg-background pl-8 pr-3 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
          />
        </div>
        <div className="flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Type:</span>
          {allTypes.sort().map((t) => (
            <button
              key={t}
              onClick={() => onTypeFilter(typeFilter === t ? null : t)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                typeFilter === t
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {t}
            </button>
          ))}
        </div>
        <span className="ml-auto text-xs text-muted-foreground">{components.length} component(s)</span>
      </div>

      {/* Component list */}
      {components.length === 0 ? (
        <div className="py-8 text-center text-sm text-muted-foreground">
          No components match the current filters.
        </div>
      ) : (
        <div className="space-y-1">
          {components.map((comp) => {
            const isExpanded = expandedComp === comp.id
            return (
              <div key={comp.id} className="rounded-md border border-border">
                <button
                  onClick={() => onToggleExpand(comp.id)}
                  className="flex w-full items-center gap-3 px-4 py-2.5 text-left hover:bg-accent/50 transition-colors"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  )}
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium">{comp.name}</span>
                      {comp.version && (
                        <span className="text-sm font-mono text-muted-foreground">{comp.version}</span>
                      )}
                      <Badge variant="outline" className="text-[10px]">{comp.type}</Badge>
                      <TooltipProvider>
                        <Tooltip>
                          <TooltipTrigger asChild>
                            <Badge
                              variant="outline"
                              className={`cursor-help text-[10px] ${CONFIDENCE_STYLE[comp.detection_confidence] ?? ''}`}
                            >
                              {comp.detection_confidence}
                            </Badge>
                          </TooltipTrigger>
                          <TooltipContent side="top" className="max-w-64 text-xs">
                            {CONFIDENCE_DESCRIPTION[comp.detection_confidence] ?? 'Detection confidence level'}
                          </TooltipContent>
                        </Tooltip>
                      </TooltipProvider>
                      {comp.vulnerability_count > 0 && (
                        <Badge className="bg-red-500/10 text-red-500 text-[10px] border-red-500/30">
                          {comp.vulnerability_count} CVE{comp.vulnerability_count !== 1 ? 's' : ''}
                        </Badge>
                      )}
                    </div>
                    <p className="mt-0.5 text-xs text-muted-foreground">
                      Detected via {comp.detection_source.replace(/_/g, ' ')}
                      {comp.cpe && ' \u00b7 has CPE'}
                    </p>
                  </div>
                </button>
                {isExpanded && (
                  <div className="border-t border-border bg-muted/30 px-4 py-3 space-y-2 text-xs">
                    {comp.cpe && (
                      <div>
                        <span className="font-medium text-muted-foreground">CPE: </span>
                        <span className="font-mono">{comp.cpe}</span>
                      </div>
                    )}
                    {comp.purl && (
                      <div>
                        <span className="font-medium text-muted-foreground">PURL: </span>
                        <span className="font-mono">{comp.purl}</span>
                      </div>
                    )}
                    {comp.supplier && (
                      <div>
                        <span className="font-medium text-muted-foreground">Supplier: </span>
                        <span>{comp.supplier}</span>
                      </div>
                    )}
                    {comp.file_paths && comp.file_paths.length > 0 && (
                      <div>
                        <span className="font-medium text-muted-foreground">Files: </span>
                        <span className="font-mono">{comp.file_paths.join(', ')}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ── Sorting helpers ──

type SortColumn = 'cve' | 'component' | 'cvss' | 'severity'
type SortDirection = 'asc' | 'desc'

const SEVERITY_ORDER: Record<string, number> = {
  critical: 0, high: 1, medium: 2, low: 3, info: 4,
}

function parseCveId(cveId: string): [number, number] {
  const m = cveId.match(/CVE-(\d{4})-(\d+)/)
  return m ? [parseInt(m[1]), parseInt(m[2])] : [9999, 9999]
}

// ── Vulnerabilities Tab ──

function VulnerabilitiesTab({ vulnerabilities, sevFilter, onSevFilter, resolutionFilter, onResolutionFilter, actionMenuId, onActionMenu, onResolve, justificationDialog, onJustificationDialog, justificationText, onJustificationText }: {
  vulnerabilities: SbomVulnerability[]
  sevFilter: string | null
  onSevFilter: (s: string | null) => void
  resolutionFilter: ResolutionFilter
  onResolutionFilter: (f: ResolutionFilter) => void
  actionMenuId: string | null
  onActionMenu: (id: string | null) => void
  onResolve: (vulnId: string, status: VulnerabilityResolutionStatus, justification?: string) => void
  justificationDialog: { vulnId: string; status: VulnerabilityResolutionStatus } | null
  onJustificationDialog: (d: { vulnId: string; status: VulnerabilityResolutionStatus } | null) => void
  justificationText: string
  onJustificationText: (t: string) => void
}) {
  const [selectedVuln, setSelectedVuln] = useState<string | null>(null)
  const [sortColumn, setSortColumn] = useState<SortColumn>('severity')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')

  const handleSort = (col: SortColumn) => {
    if (sortColumn === col) {
      setSortDirection(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortColumn(col)
      setSortDirection('asc')
    }
  }

  const componentCveCounts = useMemo(() => {
    const counts: Record<string, number> = {}
    for (const v of vulnerabilities) {
      const key = v.component_name ?? ''
      counts[key] = (counts[key] ?? 0) + 1
    }
    return counts
  }, [vulnerabilities])

  const sortedVulns = useMemo(() => {
    const arr = [...vulnerabilities]
    const dir = sortDirection === 'asc' ? 1 : -1

    arr.sort((a, b) => {
      switch (sortColumn) {
        case 'severity': {
          const sevA = SEVERITY_ORDER[a.effective_severity ?? a.severity] ?? 3
          const sevB = SEVERITY_ORDER[b.effective_severity ?? b.severity] ?? 3
          if (sevA !== sevB) return (sevA - sevB) * dir
          const cvssA = a.effective_cvss_score ?? a.cvss_score ?? 0
          const cvssB = b.effective_cvss_score ?? b.cvss_score ?? 0
          return (cvssB - cvssA) * dir
        }
        case 'cvss': {
          const cvssA = a.effective_cvss_score ?? a.cvss_score ?? 0
          const cvssB = b.effective_cvss_score ?? b.cvss_score ?? 0
          return (cvssB - cvssA) * dir
        }
        case 'component': {
          const countA = componentCveCounts[a.component_name ?? ''] ?? 0
          const countB = componentCveCounts[b.component_name ?? ''] ?? 0
          if (countA !== countB) return (countB - countA) * dir
          const nameCompare = (a.component_name ?? '').localeCompare(b.component_name ?? '')
          if (nameCompare !== 0) return nameCompare
          const cvssA = a.effective_cvss_score ?? a.cvss_score ?? 0
          const cvssB = b.effective_cvss_score ?? b.cvss_score ?? 0
          return cvssB - cvssA
        }
        case 'cve': {
          const [yearA, seqA] = parseCveId(a.cve_id)
          const [yearB, seqB] = parseCveId(b.cve_id)
          if (yearA !== yearB) return (yearA - yearB) * dir
          return (seqA - seqB) * dir
        }
        default:
          return 0
      }
    })

    return arr
  }, [vulnerabilities, sortColumn, sortDirection, componentCveCounts])

  const SortIcon = ({ column }: { column: SortColumn }) => {
    if (sortColumn !== column) return <ArrowUpDown className="h-3 w-3 text-muted-foreground/30" />
    return sortDirection === 'asc'
      ? <ArrowUp className="h-3 w-3" />
      : <ArrowDown className="h-3 w-3" />
  }

  return (
    <div className="space-y-4">
      {/* Resolution status filter */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Status:</span>
        {(['open', 'resolved', 'ignored', 'false_positive', 'all'] as ResolutionFilter[]).map((f) => {
          const active = resolutionFilter === f
          const label = f === 'all' ? 'All' : f === 'false_positive' ? 'False Positive' : f.charAt(0).toUpperCase() + f.slice(1)
          return (
            <button
              key={f}
              onClick={() => onResolutionFilter(f)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? 'border-primary bg-primary/10 text-primary'
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {label}
            </button>
          )
        })}
      </div>

      {/* Severity filter */}
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">Severity:</span>
        {(['critical', 'high', 'medium', 'low'] as Severity[]).map((sev) => {
          const config = SEVERITY_CONFIG[sev]
          const active = sevFilter === sev
          return (
            <button
              key={sev}
              onClick={() => onSevFilter(active ? null : sev)}
              className={`rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${
                active
                  ? config.bg
                  : 'border-border text-muted-foreground hover:text-foreground'
              }`}
            >
              {sev}
            </button>
          )
        })}
        <span className="ml-auto text-xs text-muted-foreground">{vulnerabilities.length} vulnerability(ies)</span>
      </div>

      {/* Justification dialog */}
      {justificationDialog && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="mx-4 w-full max-w-md rounded-lg border border-border bg-background p-4 shadow-lg">
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-sm font-medium">
                {justificationDialog.status === 'resolved' ? 'Resolve Vulnerability' : justificationDialog.status === 'ignored' ? 'Ignore Vulnerability' : 'Mark as False Positive'}
              </h3>
              <button onClick={() => { onJustificationDialog(null); onJustificationText('') }} className="text-muted-foreground hover:text-foreground">
                <X className="h-4 w-4" />
              </button>
            </div>
            <textarea
              value={justificationText}
              onChange={(e) => onJustificationText(e.target.value)}
              placeholder="Justification (optional)..."
              className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
              rows={3}
            />
            <div className="mt-3 flex justify-end gap-2">
              <Button variant="outline" size="sm" onClick={() => { onJustificationDialog(null); onJustificationText('') }}>
                Cancel
              </Button>
              <Button size="sm" onClick={() => onResolve(justificationDialog.vulnId, justificationDialog.status, justificationText || undefined)}>
                Confirm
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Vulnerability list */}
      {vulnerabilities.length === 0 ? (
        <div className="py-8 text-center text-sm text-muted-foreground">
          {sevFilter || resolutionFilter !== 'open' ? 'No vulnerabilities match the current filters.' : 'No vulnerabilities found. Run a scan first.'}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="py-2 pr-4 font-medium cursor-pointer select-none hover:text-foreground" onClick={() => handleSort('cve')}>
                  <span className="inline-flex items-center gap-1">CVE <SortIcon column="cve" /></span>
                </th>
                <th className="py-2 pr-4 font-medium cursor-pointer select-none hover:text-foreground" onClick={() => handleSort('component')}>
                  <span className="inline-flex items-center gap-1">Component <SortIcon column="component" /></span>
                </th>
                <th className="py-2 pr-4 font-medium cursor-pointer select-none hover:text-foreground" onClick={() => handleSort('cvss')}>
                  <span className="inline-flex items-center gap-1">CVSS <SortIcon column="cvss" /></span>
                </th>
                <th className="py-2 pr-4 font-medium cursor-pointer select-none hover:text-foreground" onClick={() => handleSort('severity')}>
                  <span className="inline-flex items-center gap-1">Severity <SortIcon column="severity" /></span>
                </th>
                <th className="py-2 pr-4 font-medium">Status</th>
                <th className="py-2 pr-4 font-medium">Description</th>
                <th className="py-2 font-medium w-10"></th>
              </tr>
            </thead>
            <tbody>
              {sortedVulns.map((v) => {
                const effectiveSev = v.effective_severity ?? v.severity
                const sevConfig = SEVERITY_CONFIG[effectiveSev] ?? SEVERITY_CONFIG.medium
                const Icon = sevConfig.icon
                const hasAdjustment = v.adjusted_severity && v.adjusted_severity !== v.severity
                const hasScoreAdjustment = v.adjusted_cvss_score != null && v.adjusted_cvss_score !== v.cvss_score
                const resConfig = RESOLUTION_CONFIG[v.resolution_status] ?? RESOLUTION_CONFIG.open
                return (
                  <tr key={v.id} className="border-b border-border/50 hover:bg-accent/30 cursor-pointer" onClick={() => setSelectedVuln(v.id)}>
                    <td className="py-2 pr-4">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
                        onClick={(e) => e.stopPropagation()}
                      >
                        {v.cve_id}
                        <ExternalLink className="h-2.5 w-2.5" />
                      </a>
                    </td>
                    <td className="py-2 pr-4">
                      <span className="font-medium">{v.component_name}</span>
                      {v.component_version && (
                        <span className="ml-1 font-mono text-muted-foreground">{v.component_version}</span>
                      )}
                    </td>
                    <td className="py-2 pr-4 font-mono">
                      {hasScoreAdjustment ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span>
                                {v.effective_cvss_score != null ? v.effective_cvss_score.toFixed(1) : '—'}
                                <span className="ml-1 text-muted-foreground/50 line-through text-[10px]">
                                  {v.cvss_score != null ? v.cvss_score.toFixed(1) : ''}
                                </span>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent side="top" className="max-w-72 text-xs">
                              {v.adjustment_rationale ?? 'AI-adjusted score'}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'
                      )}
                    </td>
                    <td className="py-2 pr-4">
                      {hasAdjustment ? (
                        <TooltipProvider>
                          <Tooltip>
                            <TooltipTrigger asChild>
                              <span className="inline-flex items-center gap-1">
                                <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${sevConfig.bg}`}>
                                  <Icon className="h-2.5 w-2.5" />
                                  {effectiveSev}
                                </span>
                                <span className="text-[10px] text-muted-foreground/50 line-through">{v.severity}</span>
                              </span>
                            </TooltipTrigger>
                            <TooltipContent side="top" className="max-w-72 text-xs">
                              {v.adjustment_rationale ?? 'AI-adjusted severity'}
                            </TooltipContent>
                          </Tooltip>
                        </TooltipProvider>
                      ) : (
                        <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${sevConfig.bg}`}>
                          <Icon className="h-2.5 w-2.5" />
                          {effectiveSev}
                        </span>
                      )}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${resConfig.className}`}>
                        {v.resolved_by === 'ai' && <Bot className="h-2.5 w-2.5" />}
                        {resConfig.label}
                      </span>
                    </td>
                    <td className="max-w-sm truncate py-2 text-xs text-muted-foreground">
                      {v.description ?? '—'}
                    </td>
                    <td className="py-2 relative" onClick={(e) => e.stopPropagation()}>
                      <button
                        onClick={() => onActionMenu(actionMenuId === v.id ? null : v.id)}
                        className="rounded p-1 hover:bg-accent text-muted-foreground hover:text-foreground"
                      >
                        <MoreHorizontal className="h-3.5 w-3.5" />
                      </button>
                      {actionMenuId === v.id && (
                        <div className="absolute right-0 top-full z-10 mt-1 w-44 rounded-md border border-border bg-popover p-1 shadow-md">
                          {v.resolution_status === 'open' ? (
                            <>
                              <button
                                onClick={() => { onActionMenu(null); onJustificationDialog({ vulnId: v.id, status: 'resolved' }) }}
                                className="w-full rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                              >
                                Mark as Resolved
                              </button>
                              <button
                                onClick={() => { onActionMenu(null); onJustificationDialog({ vulnId: v.id, status: 'ignored' }) }}
                                className="w-full rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                              >
                                Mark as Ignored
                              </button>
                              <button
                                onClick={() => { onActionMenu(null); onJustificationDialog({ vulnId: v.id, status: 'false_positive' }) }}
                                className="w-full rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                              >
                                Mark as False Positive
                              </button>
                            </>
                          ) : (
                            <button
                              onClick={() => onResolve(v.id, 'open')}
                              className="w-full rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                            >
                              Reopen
                            </button>
                          )}
                        </div>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Detail modal */}
      {selectedVuln && (() => {
        const v = sortedVulns.find(x => x.id === selectedVuln)
        if (!v) return null
        return (
          <VulnerabilityDetailModal
            vuln={v}
            onClose={() => setSelectedVuln(null)}
            onResolve={onResolve}
          />
        )
      })()}
    </div>
  )
}

// ── Vulnerability Detail Modal ──

function VulnerabilityDetailModal({ vuln: v, onClose, onResolve }: {
  vuln: SbomVulnerability
  onClose: () => void
  onResolve: (vulnId: string, status: VulnerabilityResolutionStatus, justification?: string) => void
}) {
  const [pendingAction, setPendingAction] = useState<VulnerabilityResolutionStatus | null>(null)
  const [justification, setJustification] = useState('')

  const effectiveSev = v.effective_severity ?? v.severity
  const sevConfig = SEVERITY_CONFIG[effectiveSev] ?? SEVERITY_CONFIG.medium
  const Icon = sevConfig.icon
  const hasAdjustment = v.adjusted_severity && v.adjusted_severity !== v.severity
  const hasScoreAdjustment = v.adjusted_cvss_score != null && v.adjusted_cvss_score !== v.cvss_score
  const resConfig = RESOLUTION_CONFIG[v.resolution_status] ?? RESOLUTION_CONFIG.open

  const handleAction = (status: VulnerabilityResolutionStatus) => {
    if (status === 'open') {
      onResolve(v.id, 'open')
      return
    }
    setPendingAction(status)
  }

  const confirmAction = () => {
    if (!pendingAction) return
    onResolve(v.id, pendingAction, justification || undefined)
    setPendingAction(null)
    setJustification('')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50" onClick={onClose}>
      <div
        className="mx-4 w-full max-w-2xl max-h-[80vh] overflow-y-auto rounded-lg border border-border bg-background shadow-lg"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="sticky top-0 z-10 flex items-center justify-between border-b border-border bg-background px-5 py-3">
          <div className="flex items-center gap-3">
            <a
              href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 font-mono text-sm font-semibold text-primary hover:underline"
            >
              {v.cve_id}
              <ExternalLink className="h-3 w-3" />
            </a>
            <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${sevConfig.bg}`}>
              <Icon className="h-2.5 w-2.5" />
              {effectiveSev}
            </span>
            {hasAdjustment && (
              <span className="text-[10px] text-muted-foreground/60 line-through">{v.severity}</span>
            )}
          </div>
          <button onClick={onClose} className="rounded p-1 text-muted-foreground hover:bg-accent hover:text-foreground">
            <X className="h-4 w-4" />
          </button>
        </div>

        <div className="space-y-5 px-5 py-4">
          {/* Summary row */}
          <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">CVSS Score</p>
              <p className="mt-0.5 font-mono text-sm font-semibold">
                {v.effective_cvss_score != null ? v.effective_cvss_score.toFixed(1) : v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
                {hasScoreAdjustment && (
                  <span className="ml-1.5 text-[10px] font-normal text-muted-foreground/50 line-through">
                    {v.cvss_score != null ? v.cvss_score.toFixed(1) : ''}
                  </span>
                )}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Status</p>
              <p className="mt-0.5">
                <span className={`inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium ${resConfig.className}`}>
                  {v.resolved_by === 'ai' && <Bot className="h-2.5 w-2.5" />}
                  {resConfig.label}
                </span>
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Component</p>
              <p className="mt-0.5 text-sm">
                <span className="font-medium">{v.component_name}</span>
                {v.component_version && (
                  <span className="ml-1 font-mono text-muted-foreground">{v.component_version}</span>
                )}
              </p>
            </div>
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Published</p>
              <p className="mt-0.5 text-sm text-muted-foreground">
                {v.published_date ? formatDate(v.published_date) : '—'}
              </p>
            </div>
          </div>

          {/* CVSS Vector */}
          {v.cvss_vector && (
            <div>
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">CVSS Vector</p>
              <p className="mt-1 font-mono text-xs text-muted-foreground break-all">{v.cvss_vector}</p>
            </div>
          )}

          {/* Description */}
          <div>
            <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Description</p>
            <p className="mt-1 text-sm leading-relaxed">{v.description ?? 'No description available.'}</p>
          </div>

          {/* AI Assessment */}
          {(hasAdjustment || hasScoreAdjustment || v.adjustment_rationale) && (
            <div className="rounded-md border border-border bg-muted/30 p-4">
              <div className="flex items-center gap-2 mb-2">
                <Bot className="h-3.5 w-3.5 text-muted-foreground" />
                <p className="text-xs font-medium">AI Assessment</p>
              </div>
              {(hasAdjustment || hasScoreAdjustment) && (
                <div className="mb-2 flex flex-wrap items-center gap-3 text-xs">
                  {hasAdjustment && (
                    <span>
                      Severity: <span className="line-through text-muted-foreground">{v.severity}</span>
                      {' → '}
                      <span className="font-medium">{v.adjusted_severity}</span>
                    </span>
                  )}
                  {hasScoreAdjustment && (
                    <span>
                      CVSS: <span className="line-through text-muted-foreground">{v.cvss_score?.toFixed(1)}</span>
                      {' → '}
                      <span className="font-medium">{v.adjusted_cvss_score?.toFixed(1)}</span>
                    </span>
                  )}
                </div>
              )}
              {v.adjustment_rationale && (
                <p className="text-sm leading-relaxed text-muted-foreground">{v.adjustment_rationale}</p>
              )}
            </div>
          )}

          {/* Resolution details */}
          {v.resolution_status !== 'open' && (
            <div className="rounded-md border border-border bg-muted/30 p-4">
              <p className="text-xs font-medium mb-2">Resolution</p>
              <div className="space-y-1.5 text-sm">
                <div className="flex gap-2">
                  <span className="text-xs text-muted-foreground w-20 shrink-0">Status:</span>
                  <span className="text-xs">{resConfig.label}</span>
                </div>
                {v.resolved_by && (
                  <div className="flex gap-2">
                    <span className="text-xs text-muted-foreground w-20 shrink-0">Resolved by:</span>
                    <span className="text-xs">{v.resolved_by === 'ai' ? 'AI Assistant' : 'User'}</span>
                  </div>
                )}
                {v.resolved_at && (
                  <div className="flex gap-2">
                    <span className="text-xs text-muted-foreground w-20 shrink-0">Resolved at:</span>
                    <span className="text-xs">{formatDate(v.resolved_at)}</span>
                  </div>
                )}
                {v.resolution_justification && (
                  <div className="mt-2">
                    <span className="text-xs text-muted-foreground">Justification:</span>
                    <p className="mt-1 text-sm leading-relaxed">{v.resolution_justification}</p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Actions */}
          <div className="border-t border-border pt-4">
            {pendingAction ? (
              <div className="space-y-3">
                <p className="text-xs font-medium">
                  {pendingAction === 'resolved' ? 'Resolve Vulnerability' : pendingAction === 'ignored' ? 'Ignore Vulnerability' : 'Mark as False Positive'}
                </p>
                <textarea
                  value={justification}
                  onChange={(e) => setJustification(e.target.value)}
                  placeholder="Justification (optional)..."
                  className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-ring"
                  rows={2}
                  autoFocus
                />
                <div className="flex justify-end gap-2">
                  <Button variant="outline" size="sm" onClick={() => { setPendingAction(null); setJustification('') }}>
                    Cancel
                  </Button>
                  <Button size="sm" onClick={confirmAction}>
                    Confirm
                  </Button>
                </div>
              </div>
            ) : (
              <div className="flex items-center gap-2">
                {v.resolution_status === 'open' ? (
                  <>
                    <Button variant="outline" size="sm" onClick={() => handleAction('resolved')}>
                      Mark as Resolved
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleAction('ignored')}>
                      Mark as Ignored
                    </Button>
                    <Button variant="outline" size="sm" onClick={() => handleAction('false_positive')}>
                      Mark as False Positive
                    </Button>
                  </>
                ) : (
                  <Button variant="outline" size="sm" onClick={() => handleAction('open')}>
                    Reopen
                  </Button>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
