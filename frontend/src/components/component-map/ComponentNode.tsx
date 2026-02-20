import { memo } from 'react'
import { Handle, Position, type NodeProps } from '@xyflow/react'
import { Cpu, Package, Terminal, Settings, Play, Layers, Puzzle } from 'lucide-react'
import type { ComponentNodeType } from '@/types'

export interface ComponentNodeData extends Record<string, unknown> {
  label: string
  nodeType: ComponentNodeType
  path: string
  size: number
  metadata: Record<string, unknown>
}

const nodeStyles: Record<ComponentNodeType, { bg: string; border: string; icon: typeof Cpu }> = {
  binary:      { bg: 'bg-blue-500/10',   border: 'border-blue-500/40',   icon: Cpu },
  library:     { bg: 'bg-purple-500/10',  border: 'border-purple-500/40', icon: Package },
  script:      { bg: 'bg-green-500/10',   border: 'border-green-500/40',  icon: Terminal },
  config:      { bg: 'bg-orange-500/10',  border: 'border-orange-500/40', icon: Settings },
  init_script:    { bg: 'bg-yellow-500/10',  border: 'border-yellow-500/40', icon: Play },
  kernel_module:  { bg: 'bg-red-500/10',     border: 'border-red-500/40',    icon: Puzzle },
}

const iconColor: Record<ComponentNodeType, string> = {
  binary:      'text-blue-400',
  library:     'text-purple-400',
  script:      'text-green-400',
  config:      'text-orange-400',
  init_script:    'text-yellow-400',
  kernel_module:  'text-red-400',
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}K`
  return `${(bytes / (1024 * 1024)).toFixed(1)}M`
}

function ComponentNodeComponent({ data, selected }: NodeProps) {
  const nodeData = data as unknown as ComponentNodeData
  const isCluster = !!nodeData.metadata?.isCluster
  const style = nodeStyles[nodeData.nodeType] ?? nodeStyles.binary
  const Icon = isCluster ? Layers : style.icon
  const color = iconColor[nodeData.nodeType] ?? 'text-blue-400'

  return (
    <>
      <Handle type="target" position={Position.Left} className="!h-2 !w-2 !border-border !bg-muted-foreground" />
      <div
        className={`flex items-center gap-2 rounded-lg border px-3 py-2 ${style.bg} ${style.border} ${
          isCluster ? 'border-dashed' : ''
        } ${selected ? 'ring-2 ring-ring' : ''}`}
      >
        <Icon className={`h-4 w-4 shrink-0 ${color}`} />
        <div className="min-w-0">
          <div className="truncate text-xs font-medium text-foreground" style={{ maxWidth: isCluster ? 160 : 140 }}>
            {nodeData.label}
          </div>
          <div className="text-[10px] text-muted-foreground">
            {formatSize(nodeData.size)}
            {isCluster && <span className="ml-1">&middot; click to expand</span>}
          </div>
        </div>
      </div>
      <Handle type="source" position={Position.Right} className="!h-2 !w-2 !border-border !bg-muted-foreground" />
    </>
  )
}

export default memo(ComponentNodeComponent)
