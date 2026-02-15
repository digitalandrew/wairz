import { useState, useEffect, useCallback } from 'react'
import { useParams } from 'react-router-dom'
import { FolderTree, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { useExplorerStore } from '@/stores/explorerStore'
import { useChatStore } from '@/stores/chatStore'
import FileTree from '@/components/explorer/FileTree'
import FileViewer from '@/components/explorer/FileViewer'
import ChatPanel from '@/components/chat/ChatPanel'

export default function ExplorePage() {
  const { projectId } = useParams<{ projectId: string }>()
  const resetExplorer = useExplorerStore((s) => s.reset)
  const loadDocuments = useExplorerStore((s) => s.loadDocuments)
  const resetChat = useChatStore((s) => s.reset)
  const [chatOpen, setChatOpen] = useState(false)
  const [treeOpen, setTreeOpen] = useState(true)

  useEffect(() => {
    if (projectId) {
      loadDocuments(projectId)
    }
    return () => {
      resetExplorer()
      resetChat()
    }
  }, [projectId, loadDocuments, resetExplorer, resetChat])

  const handleRequestChat = useCallback(() => {
    setChatOpen(true)
  }, [])

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

      {/* Center panel: file viewer */}
      <div className="relative flex min-w-0 flex-1 flex-col">
        {!treeOpen && (
          <button
            onClick={() => setTreeOpen(true)}
            className="absolute left-2 top-2 z-10 rounded border border-border bg-background p-1 text-muted-foreground shadow-sm hover:bg-accent hover:text-accent-foreground"
            title="Show file tree"
          >
            <PanelLeftOpen className="h-4 w-4" />
          </button>
        )}
        <FileViewer />
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
