import { useState, useEffect, useCallback, useRef } from 'react'
import { useParams, useSearchParams } from 'react-router-dom'
import { FolderTree, PanelLeftClose, PanelLeftOpen, TerminalSquare } from 'lucide-react'
import { useExplorerStore } from '@/stores/explorerStore'
import { useChatStore } from '@/stores/chatStore'
import FileTree from '@/components/explorer/FileTree'
import FileViewer from '@/components/explorer/FileViewer'
import ChatPanel from '@/components/chat/ChatPanel'
import TerminalPanel from '@/components/explorer/TerminalPanel'

export default function ExplorePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const [searchParams, setSearchParams] = useSearchParams()
  const resetExplorer = useExplorerStore((s) => s.reset)
  const loadDocuments = useExplorerStore((s) => s.loadDocuments)
  const navigateToPath = useExplorerStore((s) => s.navigateToPath)
  const resetChat = useChatStore((s) => s.reset)
  const [chatOpen, setChatOpen] = useState(false)
  const [treeOpen, setTreeOpen] = useState(true)
  const [terminalOpen, setTerminalOpen] = useState(false)
  const [terminalHeight, setTerminalHeight] = useState(250)
  const draggingRef = useRef(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (projectId) {
      loadDocuments(projectId)
    }
    return () => {
      resetExplorer()
      resetChat()
    }
  }, [projectId, loadDocuments, resetExplorer, resetChat])

  // Handle ?path= query parameter: expand tree and select file
  useEffect(() => {
    const pathParam = searchParams.get('path')
    if (!projectId || !pathParam) return
    // Clear the query param so it doesn't re-trigger on re-renders
    setSearchParams({}, { replace: true })
    navigateToPath(projectId, pathParam)
  }, [projectId, searchParams, setSearchParams, navigateToPath])

  const handleRequestChat = useCallback(() => {
    setChatOpen(true)
  }, [])

  // Vertical resize drag handler for terminal panel
  const handleDragStart = useCallback((e: React.MouseEvent) => {
    e.preventDefault()
    draggingRef.current = true

    const startY = e.clientY
    const startHeight = terminalHeight

    const onMouseMove = (moveEvent: MouseEvent) => {
      if (!draggingRef.current) return
      const delta = startY - moveEvent.clientY
      const newHeight = Math.min(600, Math.max(100, startHeight + delta))
      setTerminalHeight(newHeight)
    }

    const onMouseUp = () => {
      draggingRef.current = false
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [terminalHeight])

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Left panel: file tree */}
      {treeOpen && (
        <div className="flex w-72 shrink-0 flex-col border-r border-border">
          <div className="flex items-center gap-2 border-b border-border px-4 py-2">
            <FolderTree className="h-4 w-4 text-muted-foreground" />
            <span className="text-sm font-medium">Files</span>
            <button
              onClick={() => setTreeOpen(false)}
              className="ml-auto rounded p-0.5 text-muted-foreground hover:bg-accent hover:text-accent-foreground"
              title="Collapse panel"
            >
              <PanelLeftClose className="h-4 w-4" />
            </button>
          </div>
          <FileTree onRequestChat={handleRequestChat} />
        </div>
      )}

      {/* Center panel: file viewer + terminal */}
      <div ref={containerRef} className="relative flex min-w-0 flex-1 flex-col">
        {!treeOpen && (
          <button
            onClick={() => setTreeOpen(true)}
            className="absolute left-2 top-2 z-10 rounded border border-border bg-background p-1 text-muted-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            title="Show file tree"
          >
            <PanelLeftOpen className="h-4 w-4" />
          </button>
        )}

        {/* File viewer (takes remaining space) */}
        <div className="min-h-0 flex-1">
          <FileViewer />
        </div>

        {/* Drag handle + terminal panel */}
        {terminalOpen && (
          <>
            <div
              onMouseDown={handleDragStart}
              className="h-1 shrink-0 cursor-row-resize border-t border-border bg-background hover:bg-accent"
            />
            <div style={{ height: terminalHeight }} className="shrink-0">
              <TerminalPanel
                projectId={projectId}
                isOpen={terminalOpen}
                onClose={() => setTerminalOpen(false)}
              />
            </div>
          </>
        )}

        {/* Terminal toggle — bottom-left */}
        {!terminalOpen && (
          <button
            onClick={() => setTerminalOpen(true)}
            className="absolute bottom-4 left-4 z-10 flex items-center gap-2 rounded-md border border-border bg-background px-3 py-2 text-sm font-medium text-muted-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            title="Open terminal"
          >
            <TerminalSquare className="h-4 w-4" />
            Terminal
          </button>
        )}

        {/* Chat toggle — bottom-right */}
        {!chatOpen && (
          <ChatPanel isOpen={false} onToggle={() => setChatOpen(true)} />
        )}
      </div>

      {/* Right panel: chat */}
      {chatOpen && (
        <ChatPanel isOpen={true} onToggle={() => setChatOpen(false)} />
      )}
    </div>
  )
}
