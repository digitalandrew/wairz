import { useEffect, useRef, useState, useCallback } from 'react'
import { Tree, type NodeRendererProps } from 'react-arborist'
import { ChevronRight, Loader2, MessageSquare, Paperclip } from 'lucide-react'
import { useParams } from 'react-router-dom'
import {
  useExplorerStore,
  isPlaceholder,
  type TreeNode,
} from '@/stores/explorerStore'
import { useChatStore } from '@/stores/chatStore'
import { getFileIcon } from '@/utils/fileIcons'
import { formatFileSize } from '@/utils/format'

interface FileTreeProps {
  onRequestChat?: () => void
}

interface ContextMenuState {
  x: number
  y: number
  node: TreeNode
}

function Node({ node, style }: NodeRendererProps<TreeNode>) {
  const data = node.data
  const placeholder = isPlaceholder(data)

  if (placeholder) {
    return (
      <div style={style} className="flex items-center gap-1.5 px-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        <span>Loading…</span>
      </div>
    )
  }

  const Icon = getFileIcon(data.name, data.fileType, node.isOpen)
  const isDir = data.fileType === 'directory'

  return (
    <div
      style={style}
      className={`flex cursor-pointer items-center gap-1.5 rounded-sm px-2 text-sm ${
        node.isSelected
          ? 'bg-accent text-accent-foreground'
          : 'hover:bg-accent/50'
      }`}
      onClick={(e) => {
        if (isDir) {
          node.toggle()
        }
        node.handleClick(e)
      }}
    >
      {isDir ? (
        <ChevronRight
          className={`h-3 w-3 shrink-0 text-muted-foreground transition-transform ${
            node.isOpen ? 'rotate-90' : ''
          }`}
        />
      ) : (
        <span className="w-3 shrink-0" />
      )}
      <Icon className="h-4 w-4 shrink-0 text-muted-foreground" />
      <span className="truncate">{data.name}</span>
      {data.symlinkTarget && (
        <span className="truncate text-xs text-muted-foreground">
          → {data.symlinkTarget}
        </span>
      )}
      {data.fileType === 'file' && data.size > 0 && (
        <span className="ml-auto shrink-0 text-xs text-muted-foreground">
          {formatFileSize(data.size)}
        </span>
      )}
    </div>
  )
}

export default function FileTree({ onRequestChat }: FileTreeProps) {
  const { projectId } = useParams<{ projectId: string }>()
  const {
    treeData,
    treeError,
    loadRootDirectory,
    loadDirectory,
    selectFile,
  } = useExplorerStore()
  const addAttachment = useChatStore((s) => s.addAttachment)

  const containerRef = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState(400)
  const [contextMenu, setContextMenu] = useState<ContextMenuState | null>(null)

  // Measure container height
  useEffect(() => {
    const el = containerRef.current
    if (!el) return
    const observer = new ResizeObserver((entries) => {
      for (const entry of entries) {
        setHeight(entry.contentRect.height)
      }
    })
    observer.observe(el)
    return () => observer.disconnect()
  }, [])

  // Load root on mount
  useEffect(() => {
    if (projectId) loadRootDirectory(projectId)
  }, [projectId, loadRootDirectory])

  // Close context menu on click outside
  useEffect(() => {
    if (!contextMenu) return
    const close = () => setContextMenu(null)
    window.addEventListener('click', close)
    return () => window.removeEventListener('click', close)
  }, [contextMenu])

  const handleToggle = useCallback(
    (id: string) => {
      if (!projectId) return
      const findNode = (nodes: TreeNode[]): TreeNode | null => {
        for (const n of nodes) {
          if (n.id === id) return n
          if (n.children) {
            const found = findNode(n.children)
            if (found) return found
          }
        }
        return null
      }
      const node = findNode(treeData)
      if (
        node?.children?.length === 1 &&
        isPlaceholder(node.children[0])
      ) {
        loadDirectory(projectId, id)
      }
    },
    [projectId, treeData, loadDirectory],
  )

  const handleActivate = useCallback(
    (node: { data: TreeNode }) => {
      if (!projectId) return
      if (node.data.fileType !== 'directory') {
        selectFile(projectId, node.data)
      }
    },
    [projectId, selectFile],
  )

  const handleContextMenu = useCallback(
    (e: React.MouseEvent) => {
      // Find the closest tree row element
      const target = e.target as HTMLElement
      const row = target.closest('[data-testid="row"]') || target.closest('[role="treeitem"]')
      if (!row) return

      // Get the node id from the tree row
      const nodeId = row.getAttribute('data-testid')?.replace('row-', '')
      if (!nodeId) return

      const findNode = (nodes: TreeNode[]): TreeNode | null => {
        for (const n of nodes) {
          if (n.id === nodeId) return n
          if (n.children) {
            const found = findNode(n.children)
            if (found) return found
          }
        }
        return null
      }

      const node = findNode(treeData)
      if (!node || node.fileType === 'directory') return

      e.preventDefault()
      setContextMenu({ x: e.clientX, y: e.clientY, node })
    },
    [treeData],
  )

  const handleAskAI = useCallback(() => {
    if (!contextMenu) return
    const node = contextMenu.node
    addAttachment({ path: node.id, name: node.name })
    setContextMenu(null)
    onRequestChat?.()
  }, [contextMenu, addAttachment, onRequestChat])

  const handleAttachToChat = useCallback(() => {
    if (!contextMenu) return
    const node = contextMenu.node
    addAttachment({ path: node.id, name: node.name })
    setContextMenu(null)
  }, [contextMenu, addAttachment])

  if (treeError) {
    return (
      <div className="p-4 text-sm text-destructive">
        Failed to load files: {treeError}
      </div>
    )
  }

  return (
    <div ref={containerRef} className="relative flex-1 overflow-hidden" onContextMenu={handleContextMenu}>
      <Tree<TreeNode>
        data={treeData}
        width="100%"
        height={height}
        rowHeight={28}
        indent={16}
        openByDefault={false}
        disableDrag
        disableDrop
        disableEdit
        disableMultiSelection
        onToggle={handleToggle}
        onActivate={handleActivate}
      >
        {Node}
      </Tree>

      {/* Context menu */}
      {contextMenu && (
        <div
          className="fixed z-50 min-w-[180px] rounded-md border border-border bg-popover py-1 text-sm shadow-md"
          style={{ left: contextMenu.x, top: contextMenu.y }}
        >
          <button
            onClick={handleAskAI}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent hover:text-accent-foreground"
          >
            <MessageSquare className="h-3.5 w-3.5" />
            Ask AI about this file
          </button>
          <button
            onClick={handleAttachToChat}
            className="flex w-full items-center gap-2 px-3 py-1.5 text-left hover:bg-accent hover:text-accent-foreground"
          >
            <Paperclip className="h-3.5 w-3.5" />
            Attach to chat
          </button>
        </div>
      )}
    </div>
  )
}
