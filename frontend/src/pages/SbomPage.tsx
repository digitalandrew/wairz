import { useCallback, useEffect, useState } from 'react'
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
} from '@/api/sbom'
import type {
  SbomComponent,
  SbomVulnerability,
  SbomSummary,
  Severity,
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
  const [expandedComp, setExpandedComp] = useState<string | null>(null)

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
        const vulns = await getVulnerabilities(projectId).catch(() => [])
        setVulnerabilities(vulns)
      }
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    loadData()
  }, [loadData])

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
            label="Medium / Low"
            value={(summary.vulns_by_severity['medium'] ?? 0) + (summary.vulns_by_severity['low'] ?? 0)}
            detail={`${summary.vulns_by_severity['medium'] ?? 0} medium, ${summary.vulns_by_severity['low'] ?? 0} low`}
          />
        </div>
      )}

      {/* Scan button */}
      {hasComponents && (
        <div className="flex items-center gap-3">
          <Button
            onClick={() => handleScan(false)}
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

// ── Vulnerabilities Tab ──

function VulnerabilitiesTab({ vulnerabilities, sevFilter, onSevFilter }: {
  vulnerabilities: SbomVulnerability[]
  sevFilter: string | null
  onSevFilter: (s: string | null) => void
}) {
  return (
    <div className="space-y-4">
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

      {/* Vulnerability list */}
      {vulnerabilities.length === 0 ? (
        <div className="py-8 text-center text-sm text-muted-foreground">
          {sevFilter ? 'No vulnerabilities match the current filter.' : 'No vulnerabilities found. Run a scan first.'}
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs text-muted-foreground">
                <th className="py-2 pr-4 font-medium">CVE</th>
                <th className="py-2 pr-4 font-medium">Component</th>
                <th className="py-2 pr-4 font-medium">CVSS</th>
                <th className="py-2 pr-4 font-medium">Severity</th>
                <th className="py-2 font-medium">Description</th>
              </tr>
            </thead>
            <tbody>
              {vulnerabilities.map((v) => {
                const sevConfig = SEVERITY_CONFIG[v.severity] ?? SEVERITY_CONFIG.medium
                const Icon = sevConfig.icon
                return (
                  <tr key={v.id} className="border-b border-border/50 hover:bg-accent/30">
                    <td className="py-2 pr-4">
                      <a
                        href={`https://nvd.nist.gov/vuln/detail/${v.cve_id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="inline-flex items-center gap-1 font-mono text-xs text-primary hover:underline"
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
                      {v.cvss_score != null ? v.cvss_score.toFixed(1) : '—'}
                    </td>
                    <td className="py-2 pr-4">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${sevConfig.bg}`}>
                        <Icon className="h-2.5 w-2.5" />
                        {v.severity}
                      </span>
                    </td>
                    <td className="max-w-md truncate py-2 text-xs text-muted-foreground">
                      {v.description ?? '—'}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
