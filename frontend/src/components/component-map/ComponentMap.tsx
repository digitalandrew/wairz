import { useState, useCallback, useMemo, useEffect } from 'react'
import {
  ReactFlow,
  Background,
  MiniMap,
  type Node,
  type Edge,
  type EdgeMouseHandler,
  type NodeMouseHandler,
  useNodesState,
  useEdgesState,
  ReactFlowProvider,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from '@dagrejs/dagre'
import { useNavigate, useParams } from 'react-router-dom'
import { MessageSquare, ExternalLink } from 'lucide-react'
import { useChatStore } from '@/stores/chatStore'
import type {
  ComponentGraph,
  ComponentNode as CNode,
  ComponentEdge as CEdge,
  ComponentNodeType,
  ComponentEdgeType,
} from '@/types'
import ComponentNodeComponent, { type ComponentNodeData } from './ComponentNode'
import EdgeDetails from './EdgeDetails'
import MapControls from './MapControls'

const nodeTypes = { component: ComponentNodeComponent }

const NODE_WIDTH = 180
const NODE_HEIGHT = 50

const edgeStyles: Record<ComponentEdgeType, { stroke: string; strokeDasharray?: string; strokeWidth: number }> = {
  links_library:     { stroke: '#6b7280', strokeWidth: 1.5 },
  imports_functions:  { stroke: '#6b7280', strokeDasharray: '5 3', strokeWidth: 1 },
  sources_script:    { stroke: '#6b7280', strokeDasharray: '2 2', strokeWidth: 1 },
  executes:          { stroke: '#6b7280', strokeDasharray: '2 2', strokeWidth: 1.5 },
  starts_service:    { stroke: '#6b7280', strokeWidth: 2 },
  configures:        { stroke: '#6b728066', strokeWidth: 1 },
}

const edgeTypeLabels: Record<ComponentEdgeType, string> = {
  links_library: 'links',
  imports_functions: 'imports functions from',
  sources_script: 'sources',
  executes: 'executes',
  starts_service: 'starts',
  configures: 'configures',
}

const ALL_TYPES = new Set<ComponentNodeType>(['binary', 'library', 'script', 'config', 'init_script'])

const CLUSTER_THRESHOLD = 200
const MIN_CLUSTER_SIZE = 3

// ── Clustering ─────────────────────────────────────────────────────────

interface ClusterInfo {
  dir: string
  members: string[]
}

function clusterGraph(
  nodes: CNode[],
  edges: CEdge[],
  expandedClusters: Set<string>,
): { nodes: CNode[]; edges: CEdge[]; clusters: Map<string, ClusterInfo> } {
  // Group nodes by parent directory
  const dirGroups = new Map<string, CNode[]>()
  for (const node of nodes) {
    const lastSlash = node.id.lastIndexOf('/')
    const dir = lastSlash > 0 ? node.id.substring(0, lastSlash) : '/'
    if (!dirGroups.has(dir)) dirGroups.set(dir, [])
    dirGroups.get(dir)!.push(node)
  }

  const resultNodes: CNode[] = []
  const clusterMembership = new Map<string, string>() // nodeId -> clusterId
  const clusters = new Map<string, ClusterInfo>()

  for (const [dir, members] of dirGroups) {
    if (members.length >= MIN_CLUSTER_SIZE && !expandedClusters.has(dir)) {
      const clusterId = `__cluster__:${dir}`
      const dirName = dir.split('/').filter(Boolean).pop() ?? dir

      // Find the dominant type for visual styling
      const typeCounts = new Map<ComponentNodeType, number>()
      for (const m of members) {
        typeCounts.set(m.type, (typeCounts.get(m.type) ?? 0) + 1)
      }
      let dominantType: ComponentNodeType = 'binary'
      let maxCount = 0
      for (const [t, c] of typeCounts) {
        if (c > maxCount) { dominantType = t; maxCount = c }
      }

      resultNodes.push({
        id: clusterId,
        label: `${dirName}/ (${members.length})`,
        type: dominantType,
        path: dir,
        size: members.reduce((s, n) => s + n.size, 0),
        metadata: { isCluster: true, count: members.length },
      })

      clusters.set(clusterId, {
        dir,
        members: members.map((m) => m.id),
      })

      for (const m of members) {
        clusterMembership.set(m.id, clusterId)
      }
    } else {
      resultNodes.push(...members)
    }
  }

  // Remap and deduplicate edges
  const seen = new Set<string>()
  const remappedEdges: CEdge[] = []
  for (const e of edges) {
    const source = clusterMembership.get(e.source) ?? e.source
    const target = clusterMembership.get(e.target) ?? e.target
    if (source === target) continue // skip self-loops from clustering
    const key = `${source}-${target}-${e.type}`
    if (seen.has(key)) continue
    seen.add(key)
    remappedEdges.push({ ...e, source, target })
  }

  return { nodes: resultNodes, edges: remappedEdges, clusters }
}

// ── Layout ─────────────────────────────────────────────────────────────

function getLayoutedElements(
  nodes: Node<ComponentNodeData>[],
  edges: Edge[],
): { nodes: Node<ComponentNodeData>[]; edges: Edge[] } {
  const g = new dagre.graphlib.Graph()
  g.setDefaultEdgeLabel(() => ({}))
  g.setGraph({ rankdir: 'LR', ranksep: 100, nodesep: 30 })

  nodes.forEach((node) => {
    g.setNode(node.id, { width: NODE_WIDTH, height: NODE_HEIGHT })
  })
  edges.forEach((edge) => {
    g.setEdge(edge.source, edge.target)
  })

  dagre.layout(g)

  const layoutedNodes = nodes.map((node) => {
    const pos = g.node(node.id)
    return {
      ...node,
      position: { x: pos.x - NODE_WIDTH / 2, y: pos.y - NODE_HEIGHT / 2 },
    }
  })

  return { nodes: layoutedNodes, edges }
}

// ── Main component ─────────────────────────────────────────────────────

interface SelectedEdge {
  edgeType: ComponentEdgeType
  details: Record<string, unknown>
  source: string
  target: string
  position: { x: number; y: number }
}

interface ContextMenuState {
  x: number
  y: number
  kind: 'node' | 'edge'
  nodeId?: string
  nodeLabel?: string
  edgeId?: string
  edgeSource?: string
  edgeTarget?: string
  edgeType?: ComponentEdgeType
}

interface ComponentMapInnerProps {
  graph: ComponentGraph
  onRequestChat?: () => void
}

function ComponentMapInner({ graph, onRequestChat }: ComponentMapInnerProps) {
  const navigate = useNavigate()
  const { projectId } = useParams<{ projectId: string }>()
  const addAttachment = useChatStore((s) => s.addAttachment)
  const [visibleTypes, setVisibleTypes] = useState<Set<ComponentNodeType>>(new Set(ALL_TYPES))
  const [searchQuery, setSearchQuery] = useState('')
  const [selectedEdge, setSelectedEdge] = useState<SelectedEdge | null>(null)
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null)

  // Clustering state
  const [clusteringEnabled, setClusteringEnabled] = useState(graph.nodes.length >= CLUSTER_THRESHOLD)
  const [expandedClusters, setExpandedClusters] = useState<Set<string>>(new Set())

  // Close context menu on any click
  useEffect(() => {
    if (!contextMenu) return
    const close = () => setContextMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [contextMenu])

  // Apply clustering if enabled and graph is large
  const { nodes: processedNodes, edges: processedEdges, clusters } = useMemo(() => {
    // First filter by visible types
    const filteredNodes = graph.nodes.filter((n: CNode) => visibleTypes.has(n.type))
    const filteredNodeIds = new Set(filteredNodes.map((n: CNode) => n.id))
    const filteredEdges = graph.edges.filter(
      (e: CEdge) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target),
    )

    if (clusteringEnabled && filteredNodes.length >= CLUSTER_THRESHOLD) {
      return clusterGraph(filteredNodes, filteredEdges, expandedClusters)
    }
    return { nodes: filteredNodes, edges: filteredEdges, clusters: new Map<string, ClusterInfo>() }
  }, [graph.nodes, graph.edges, visibleTypes, clusteringEnabled, expandedClusters])

  // Build a lookup for edge details keyed by reactflow edge id
  const edgeDetailsMap = useMemo(() => {
    const map = new Map<string, { type: ComponentEdgeType; details: Record<string, unknown>; source: string; target: string }>()
    processedEdges.forEach((e) => {
      const id = `${e.source}-${e.target}-${e.type}`
      map.set(id, { type: e.type as ComponentEdgeType, details: e.details, source: e.source, target: e.target })
    })
    return map
  }, [processedEdges])

  // Determine which node IDs match the current search
  const matchedNodeIds = useMemo(() => {
    if (!searchQuery.trim()) return null
    const q = searchQuery.toLowerCase()
    return new Set(
      processedNodes
        .filter((n) => n.label.toLowerCase().includes(q) || n.path.toLowerCase().includes(q))
        .map((n) => n.id)
    )
  }, [searchQuery, processedNodes])

  // Build ReactFlow nodes
  const initialNodes: Node<ComponentNodeData>[] = useMemo(() => {
    return processedNodes.map((n) => ({
      id: n.id,
      type: 'component',
      position: { x: 0, y: 0 },
      data: {
        label: n.label,
        nodeType: n.type,
        path: n.path,
        size: n.size,
        metadata: n.metadata,
      },
      style: matchedNodeIds && !matchedNodeIds.has(n.id)
        ? { opacity: 0.25 }
        : undefined,
    }))
  }, [processedNodes, matchedNodeIds])

  // Build ReactFlow edges
  const initialEdges: Edge[] = useMemo(() => {
    return processedEdges.map((e) => {
      const style = edgeStyles[e.type as ComponentEdgeType] ?? edgeStyles.links_library
      const dimmed = matchedNodeIds && (!matchedNodeIds.has(e.source) && !matchedNodeIds.has(e.target))
      return {
        id: `${e.source}-${e.target}-${e.type}`,
        source: e.source,
        target: e.target,
        animated: e.type === 'starts_service',
        style: {
          ...style,
          opacity: dimmed ? 0.1 : undefined,
        },
      }
    })
  }, [processedEdges, matchedNodeIds])

  // Apply dagre layout
  const { nodes: layoutedNodes, edges: layoutedEdges } = useMemo(
    () => getLayoutedElements(initialNodes, initialEdges),
    [initialNodes, initialEdges],
  )

  const [nodes, setNodes, onNodesChange] = useNodesState(layoutedNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(layoutedEdges)

  // Update nodes/edges when layout changes
  useEffect(() => {
    setNodes(layoutedNodes)
    setEdges(layoutedEdges)
  }, [layoutedNodes, layoutedEdges, setNodes, setEdges])

  const handleNodeClick = useCallback(
    (_: React.MouseEvent, node: Node) => {
      const data = node.data as unknown as ComponentNodeData
      // If it's a cluster node, toggle expansion
      if (data.metadata?.isCluster) {
        const clusterInfo = clusters.get(node.id)
        if (clusterInfo) {
          setExpandedClusters((prev) => {
            const next = new Set(prev)
            if (next.has(clusterInfo.dir)) {
              next.delete(clusterInfo.dir)
            } else {
              next.add(clusterInfo.dir)
            }
            return next
          })
        }
        return
      }
      if (projectId) {
        navigate(`/projects/${projectId}/explore?path=${encodeURIComponent(node.id)}`)
      }
    },
    [navigate, projectId, clusters],
  )

  const handleEdgeClick: EdgeMouseHandler = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      const info = edgeDetailsMap.get(edge.id)
      if (info) {
        setSelectedEdge({
          edgeType: info.type,
          details: info.details,
          source: info.source,
          target: info.target,
          position: { x: event.clientX, y: event.clientY },
        })
      }
    },
    [edgeDetailsMap],
  )

  const handlePaneClick = useCallback(() => {
    setSelectedEdge(null)
    setContextMenu(null)
  }, [])

  // Right-click context menu on nodes
  const handleNodeContextMenu: NodeMouseHandler = useCallback(
    (event: React.MouseEvent, node: Node) => {
      event.preventDefault()
      const data = node.data as unknown as ComponentNodeData
      setContextMenu({
        x: event.clientX,
        y: event.clientY,
        kind: 'node',
        nodeId: node.id,
        nodeLabel: data.label,
      })
      setSelectedEdge(null)
    },
    [],
  )

  // Right-click context menu on edges
  const handleEdgeContextMenu: EdgeMouseHandler = useCallback(
    (event: React.MouseEvent, edge: Edge) => {
      event.preventDefault()
      const info = edgeDetailsMap.get(edge.id)
      if (info) {
        setContextMenu({
          x: event.clientX,
          y: event.clientY,
          kind: 'edge',
          edgeId: edge.id,
          edgeSource: info.source,
          edgeTarget: info.target,
          edgeType: info.type,
        })
      }
      setSelectedEdge(null)
    },
    [edgeDetailsMap],
  )

  // Context menu actions
  const handleAskAIAboutNode = useCallback(() => {
    if (!contextMenu || contextMenu.kind !== 'node' || !contextMenu.nodeId) return
    addAttachment({ path: contextMenu.nodeId, name: contextMenu.nodeLabel ?? contextMenu.nodeId })
    setContextMenu(null)
    onRequestChat?.()
  }, [contextMenu, addAttachment, onRequestChat])

  const handleOpenInExplorer = useCallback(() => {
    if (!contextMenu || contextMenu.kind !== 'node' || !contextMenu.nodeId || !projectId) return
    navigate(`/projects/${projectId}/explore?path=${encodeURIComponent(contextMenu.nodeId)}`)
    setContextMenu(null)
  }, [contextMenu, projectId, navigate])

  const handleAskAIAboutEdge = useCallback(() => {
    if (!contextMenu || contextMenu.kind !== 'edge') return
    const { edgeSource, edgeTarget, edgeType } = contextMenu
    const label = edgeTypeLabels[edgeType!] ?? edgeType
    if (edgeSource) {
      addAttachment({ path: edgeSource, name: edgeSource.split('/').pop() ?? edgeSource })
    }
    setContextMenu(null)
    onRequestChat?.()
    setTimeout(() => {
      const chatInput = document.querySelector<HTMLTextAreaElement>('[data-chat-input]')
      if (chatInput) {
        const prompt = `What is the relationship between ${edgeSource} and ${edgeTarget}? (${label})`
        chatInput.value = prompt
        chatInput.dispatchEvent(new Event('input', { bubbles: true }))
        chatInput.focus()
      }
    }, 100)
  }, [contextMenu, addAttachment, onRequestChat])

  const handleToggleType = useCallback((type: ComponentNodeType) => {
    setVisibleTypes((prev) => {
      const next = new Set(prev)
      if (next.has(type)) {
        next.delete(type)
      } else {
        next.add(type)
      }
      return next
    })
  }, [])

  const handleToggleClustering = useCallback(() => {
    setClusteringEnabled((v) => !v)
    setExpandedClusters(new Set())
  }, [])

  const miniMapNodeColor = useCallback((node: Node) => {
    const data = node.data as unknown as ComponentNodeData
    switch (data.nodeType) {
      case 'binary': return '#3b82f6'
      case 'library': return '#a855f7'
      case 'script': return '#22c55e'
      case 'config': return '#f97316'
      case 'init_script': return '#eab308'
      default: return '#6b7280'
    }
  }, [])

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        onNodeClick={handleNodeClick}
        onEdgeClick={handleEdgeClick}
        onNodeContextMenu={handleNodeContextMenu}
        onEdgeContextMenu={handleEdgeContextMenu}
        onPaneClick={handlePaneClick}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.1 }}
        minZoom={0.1}
        maxZoom={2}
        proOptions={{ hideAttribution: true }}
        className="bg-background"
      >
        <Background gap={20} size={1} />
        <MiniMap
          nodeColor={miniMapNodeColor}
          maskColor="rgba(0,0,0,0.6)"
          className="!bottom-3 !right-3 !rounded-md !border !border-border !bg-background/80"
          pannable
          zoomable
        />
      </ReactFlow>

      <MapControls
        visibleTypes={visibleTypes}
        onToggleType={handleToggleType}
        onSearch={setSearchQuery}
        graph={graph}
        clusteringEnabled={clusteringEnabled}
        onToggleClustering={handleToggleClustering}
        showClusterToggle={graph.nodes.length >= CLUSTER_THRESHOLD}
      />

      {/* Stats badge */}
      <div className="absolute bottom-3 left-3 z-10 rounded-md border border-border bg-background/95 px-2 py-1 text-[10px] text-muted-foreground shadow-sm backdrop-blur">
        {nodes.length} nodes &middot; {edges.length} edges
        {graph.truncated && <span className="ml-1 text-yellow-500">(truncated)</span>}
        {clusteringEnabled && expandedClusters.size > 0 && (
          <span className="ml-1">
            &middot; {expandedClusters.size} expanded
          </span>
        )}
      </div>

      {/* Edge details popover */}
      {selectedEdge && (
        <EdgeDetails
          edgeType={selectedEdge.edgeType}
          details={selectedEdge.details}
          source={selectedEdge.source}
          target={selectedEdge.target}
          position={selectedEdge.position}
          onClose={() => setSelectedEdge(null)}
        />
      )}

      {/* Context menu */}
      {contextMenu && (
        <div
          className="fixed z-50 min-w-[200px] rounded-md border border-border bg-popover py-1 text-sm shadow-md"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          {contextMenu.kind === 'node' && (
            <>
              <div className="truncate px-3 py-1 text-xs text-muted-foreground">
                {contextMenu.nodeId}
              </div>
              <div className="mx-1 my-0.5 border-t border-border" />
              <button
                onClick={handleAskAIAboutNode}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent hover:text-accent-foreground"
              >
                <MessageSquare className="h-3.5 w-3.5" />
                Ask AI about this component
              </button>
              <button
                onClick={handleOpenInExplorer}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent hover:text-accent-foreground"
              >
                <ExternalLink className="h-3.5 w-3.5" />
                Open in File Explorer
              </button>
            </>
          )}
          {contextMenu.kind === 'edge' && (
            <>
              <div className="truncate px-3 py-1 text-xs text-muted-foreground">
                {contextMenu.edgeSource} {edgeTypeLabels[contextMenu.edgeType!] ?? ''} {contextMenu.edgeTarget}
              </div>
              <div className="mx-1 my-0.5 border-t border-border" />
              <button
                onClick={handleAskAIAboutEdge}
                className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent hover:text-accent-foreground"
              >
                <MessageSquare className="h-3.5 w-3.5" />
                Ask AI about this relationship
              </button>
            </>
          )}
        </div>
      )}
    </div>
  )
}

export default function ComponentMap({ graph, onRequestChat }: { graph: ComponentGraph; onRequestChat?: () => void }) {
  return (
    <ReactFlowProvider>
      <ComponentMapInner graph={graph} onRequestChat={onRequestChat} />
    </ReactFlowProvider>
  )
}
