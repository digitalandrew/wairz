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

  // Close context menu on any click
  useEffect(() => {
    if (!contextMenu) return
    const close = () => setContextMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [contextMenu])

  // Build a lookup for edge details keyed by reactflow edge id
  const edgeDetailsMap = useMemo(() => {
    const map = new Map<string, { type: ComponentEdgeType; details: Record<string, unknown>; source: string; target: string }>()
    graph.edges.forEach((e) => {
      const id = `${e.source}-${e.target}-${e.type}`
      map.set(id, { type: e.type as ComponentEdgeType, details: e.details, source: e.source, target: e.target })
    })
    return map
  }, [graph.edges])

  // Determine which node IDs match the current search
  const matchedNodeIds = useMemo(() => {
    if (!searchQuery.trim()) return null
    const q = searchQuery.toLowerCase()
    return new Set(
      graph.nodes
        .filter((n) => n.label.toLowerCase().includes(q) || n.path.toLowerCase().includes(q))
        .map((n) => n.id)
    )
  }, [searchQuery, graph.nodes])

  // Filter nodes by visible types
  const filteredNodeIds = useMemo(() => {
    return new Set(
      graph.nodes.filter((n) => visibleTypes.has(n.type)).map((n) => n.id)
    )
  }, [graph.nodes, visibleTypes])

  // Build ReactFlow nodes
  const initialNodes: Node<ComponentNodeData>[] = useMemo(() => {
    return graph.nodes
      .filter((n) => filteredNodeIds.has(n.id))
      .map((n) => ({
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
  }, [graph.nodes, filteredNodeIds, matchedNodeIds])

  // Build ReactFlow edges
  const initialEdges: Edge[] = useMemo(() => {
    return graph.edges
      .filter((e) => filteredNodeIds.has(e.source) && filteredNodeIds.has(e.target))
      .map((e) => {
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
  }, [graph.edges, filteredNodeIds, matchedNodeIds])

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
      if (projectId) {
        navigate(`/projects/${projectId}/explore?path=${encodeURIComponent(node.id)}`)
      }
    },
    [navigate, projectId],
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
    // Attach the source file so the AI has context
    if (edgeSource) {
      addAttachment({ path: edgeSource, name: edgeSource.split('/').pop() ?? edgeSource })
    }
    setContextMenu(null)
    onRequestChat?.()
    // Add a pre-filled prompt hint by using the chat store to add a user-facing message context
    // The user can see the attachment and ask about the relationship
    // We use a brief timeout so the chat panel opens first
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
      />

      {/* Stats badge */}
      <div className="absolute bottom-3 left-3 z-10 rounded-md border border-border bg-background/95 px-2 py-1 text-[10px] text-muted-foreground shadow-sm backdrop-blur">
        {nodes.length} nodes &middot; {edges.length} edges
        {graph.truncated && <span className="ml-1 text-yellow-500">(truncated)</span>}
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
