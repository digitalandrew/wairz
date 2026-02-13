import { useEffect } from 'react'
import { FolderTree } from 'lucide-react'
import { useExplorerStore } from '@/stores/explorerStore'
import FileTree from '@/components/explorer/FileTree'
import FileViewer from '@/components/explorer/FileViewer'

export default function ExplorePage() {
  const reset = useExplorerStore((s) => s.reset)

  useEffect(() => {
    return () => reset()
  }, [reset])

  return (
    <div className="-m-6 flex h-[calc(100vh-3.5rem)]">
      {/* Left panel: file tree */}
      <div className="flex w-72 shrink-0 flex-col border-r border-border">
        <div className="flex items-center gap-2 border-b border-border px-4 py-2">
          <FolderTree className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Files</span>
        </div>
        <FileTree />
      </div>

      {/* Right panel: file viewer */}
      <div className="flex min-w-0 flex-1 flex-col">
        <FileViewer />
      </div>
    </div>
  )
}
