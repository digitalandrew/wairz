import { useState, useCallback } from 'react'
import { useReactFlow, getNodesBounds, getViewportForBounds } from '@xyflow/react'
import { toPng, toSvg } from 'html-to-image'
import { Search, Maximize, Filter, Download, Layers } from 'lucide-react'
import type { ComponentNodeType, ComponentGraph } from '@/types'
import { Checkbox } from '@/components/ui/checkbox'

const NODE_TYPE_OPTIONS: { type: ComponentNodeType; label: string; color: string }[] = [
  { type: 'binary',      label: 'Binaries',     color: 'bg-blue-500' },
  { type: 'library',     label: 'Libraries',     color: 'bg-purple-500' },
  { type: 'script',      label: 'Scripts',        color: 'bg-green-500' },
  { type: 'config',      label: 'Configs',        color: 'bg-orange-500' },
  { type: 'init_script', label: 'Init Scripts',   color: 'bg-yellow-500' },
]

interface MapControlsProps {
  visibleTypes: Set<ComponentNodeType>
  onToggleType: (type: ComponentNodeType) => void
  onSearch: (query: string) => void
  graph: ComponentGraph
  clusteringEnabled: boolean
  onToggleClustering: () => void
  showClusterToggle: boolean
}

function downloadDataUrl(dataUrl: string, filename: string) {
  const a = document.createElement('a')
  a.href = dataUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
}

const IMAGE_WIDTH = 2048
const IMAGE_HEIGHT = 1536

export default function MapControls({
  visibleTypes,
  onToggleType,
  onSearch,
  graph,
  clusteringEnabled,
  onToggleClustering,
  showClusterToggle,
}: MapControlsProps) {
  const { getNodes, fitView } = useReactFlow()
  const [searchQuery, setSearchQuery] = useState('')
  const [filterOpen, setFilterOpen] = useState(false)
  const [exportOpen, setExportOpen] = useState(false)

  const handleSearch = (value: string) => {
    setSearchQuery(value)
    onSearch(value)
  }

  const getExportOptions = useCallback(() => {
    const allNodes = getNodes()
    if (allNodes.length === 0) return null
    const nodesBounds = getNodesBounds(allNodes)
    const viewport = getViewportForBounds(nodesBounds, IMAGE_WIDTH, IMAGE_HEIGHT, 0.5, 2, 0.25)
    const el = document.querySelector('.react-flow__viewport') as HTMLElement
    if (!el || !viewport) return null
    return { el, viewport }
  }, [getNodes])

  const handleExportPNG = useCallback(() => {
    const opts = getExportOptions()
    if (!opts) return
    const { el, viewport } = opts
    toPng(el, {
      backgroundColor: '#09090b',
      width: IMAGE_WIDTH,
      height: IMAGE_HEIGHT,
      style: {
        width: `${IMAGE_WIDTH}px`,
        height: `${IMAGE_HEIGHT}px`,
        transform: `translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})`,
      },
    }).then((dataUrl) => downloadDataUrl(dataUrl, 'component-map.png'))
    setExportOpen(false)
  }, [getExportOptions])

  const handleExportSVG = useCallback(() => {
    const opts = getExportOptions()
    if (!opts) return
    const { el, viewport } = opts
    toSvg(el, {
      backgroundColor: '#09090b',
      width: IMAGE_WIDTH,
      height: IMAGE_HEIGHT,
      style: {
        width: `${IMAGE_WIDTH}px`,
        height: `${IMAGE_HEIGHT}px`,
        transform: `translate(${viewport.x}px, ${viewport.y}px) scale(${viewport.zoom})`,
      },
    }).then((dataUrl) => downloadDataUrl(dataUrl, 'component-map.svg'))
    setExportOpen(false)
  }, [getExportOptions])

  const handleExportJSON = useCallback(() => {
    const json = JSON.stringify(graph, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    downloadDataUrl(url, 'component-map.json')
    URL.revokeObjectURL(url)
    setExportOpen(false)
  }, [graph])

  return (
    <div className="absolute left-3 top-3 z-10 flex flex-col gap-2">
      {/* Search */}
      <div className="flex items-center gap-1 rounded-md border border-border bg-background/95 px-2 py-1.5 shadow-sm backdrop-blur">
        <Search className="h-3.5 w-3.5 text-muted-foreground" />
        <input
          type="text"
          placeholder="Search components..."
          value={searchQuery}
          onChange={(e) => handleSearch(e.target.value)}
          className="w-44 bg-transparent text-xs text-foreground placeholder:text-muted-foreground focus:outline-none"
        />
      </div>

      {/* Filter + Fit + Cluster + Export */}
      <div className="flex gap-1">
        <button
          onClick={() => setFilterOpen((v) => !v)}
          className={`flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs shadow-sm backdrop-blur ${
            filterOpen ? 'bg-accent text-accent-foreground' : 'bg-background/95 text-muted-foreground hover:text-foreground'
          }`}
          title="Filter by type"
        >
          <Filter className="h-3.5 w-3.5" />
          Filter
        </button>
        <button
          onClick={() => fitView({ padding: 0.1, duration: 300 })}
          className="flex items-center gap-1 rounded-md border border-border bg-background/95 px-2 py-1.5 text-xs text-muted-foreground shadow-sm backdrop-blur hover:text-foreground"
          title="Fit to view"
        >
          <Maximize className="h-3.5 w-3.5" />
        </button>
        {showClusterToggle && (
          <button
            onClick={onToggleClustering}
            className={`flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs shadow-sm backdrop-blur ${
              clusteringEnabled ? 'bg-accent text-accent-foreground' : 'bg-background/95 text-muted-foreground hover:text-foreground'
            }`}
            title={clusteringEnabled ? 'Disable clustering' : 'Cluster by directory'}
          >
            <Layers className="h-3.5 w-3.5" />
          </button>
        )}
        <div className="relative">
          <button
            onClick={() => setExportOpen((v) => !v)}
            className={`flex items-center gap-1 rounded-md border border-border px-2 py-1.5 text-xs shadow-sm backdrop-blur ${
              exportOpen ? 'bg-accent text-accent-foreground' : 'bg-background/95 text-muted-foreground hover:text-foreground'
            }`}
            title="Export"
          >
            <Download className="h-3.5 w-3.5" />
          </button>
          {exportOpen && (
            <>
              <div
                className="fixed inset-0 z-20"
                onClick={() => setExportOpen(false)}
              />
              <div className="absolute left-0 top-full z-30 mt-1 w-36 rounded-md border border-border bg-popover p-1 shadow-md">
                <button
                  onClick={handleExportPNG}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                >
                  Export as PNG
                </button>
                <button
                  onClick={handleExportSVG}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                >
                  Export as SVG
                </button>
                <button
                  onClick={handleExportJSON}
                  className="flex w-full items-center gap-2 rounded-sm px-2 py-1.5 text-left text-xs hover:bg-accent"
                >
                  Export as JSON
                </button>
              </div>
            </>
          )}
        </div>
      </div>

      {/* Filter panel */}
      {filterOpen && (
        <div className="rounded-md border border-border bg-background/95 p-2 shadow-sm backdrop-blur">
          <div className="mb-1.5 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
            Node Types
          </div>
          {NODE_TYPE_OPTIONS.map((opt) => (
            <label
              key={opt.type}
              className="flex cursor-pointer items-center gap-2 rounded px-1 py-0.5 text-xs hover:bg-accent/50"
            >
              <Checkbox
                checked={visibleTypes.has(opt.type)}
                onCheckedChange={() => onToggleType(opt.type)}
                className="h-3.5 w-3.5"
              />
              <span className={`h-2 w-2 rounded-full ${opt.color}`} />
              <span className="text-foreground/80">{opt.label}</span>
            </label>
          ))}
        </div>
      )}
    </div>
  )
}
