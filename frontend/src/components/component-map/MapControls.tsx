import { useState } from 'react'
import { useReactFlow } from '@xyflow/react'
import { Search, Maximize, Filter } from 'lucide-react'
import type { ComponentNodeType } from '@/types'
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
}

export default function MapControls({ visibleTypes, onToggleType, onSearch }: MapControlsProps) {
  const { fitView } = useReactFlow()
  const [searchQuery, setSearchQuery] = useState('')
  const [filterOpen, setFilterOpen] = useState(false)

  const handleSearch = (value: string) => {
    setSearchQuery(value)
    onSearch(value)
  }

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

      {/* Filter + Fit */}
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
