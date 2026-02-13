import { useEffect, useRef, useState, useCallback } from 'react'
import { Tree, type NodeRendererProps } from 'react-arborist'
import { Loader2 } from 'lucide-react'
import { useParams } from 'react-router-dom'
import {
  useExplorerStore,
  isPlaceholder,
  type TreeNode,
} from '@/stores/explorerStore'
import { getFileIcon } from '@/utils/fileIcons'
import { formatFileSize } from '@/utils/format'

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

  return (
    <div
      style={style}
      className={`flex cursor-pointer items-center gap-1.5 rounded-sm px-2 text-sm ${
        node.isSelected
          ? 'bg-accent text-accent-foreground'
          : 'hover:bg-accent/50'
      }`}
      onClick={(e) => node.handleClick(e)}
    >
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

export default function FileTree() {
  const { projectId } = useParams<{ projectId: string }>()
  const {
    treeData,
    treeError,
    loadRootDirectory,
    loadDirectory,
    selectFile,
  } = useExplorerStore()

  const containerRef = useRef<HTMLDivElement>(null)
  const [height, setHeight] = useState(400)

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

  const handleToggle = useCallback(
    (id: string) => {
      if (!projectId) return
      // Find the node in the tree and check if it has a placeholder child
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

  if (treeError) {
    return (
      <div className="p-4 text-sm text-destructive">
        Failed to load files: {treeError}
      </div>
    )
  }

  return (
    <div ref={containerRef} className="flex-1 overflow-hidden">
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
    </div>
  )
}
