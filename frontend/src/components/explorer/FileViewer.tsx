import { Loader2, FileSearch, AlertTriangle } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { useParams } from 'react-router-dom'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useExplorerStore } from '@/stores/explorerStore'
import { getMonacoLanguage } from '@/utils/fileIcons'
import { registerAssemblyLanguage } from '@/utils/monacoAssembly'
import { formatFileSize } from '@/utils/format'
import HexViewer from './HexViewer'
import BinaryInfo from './BinaryInfo'

export default function FileViewer() {
  const { projectId } = useParams<{ projectId: string }>()
  const { selectedNode, selectedPath, fileContent, fileInfo, contentLoading, infoLoading } =
    useExplorerStore()

  if (!selectedPath) {
    return (
      <div className="flex h-full items-center justify-center text-muted-foreground">
        <div className="flex flex-col items-center gap-2">
          <FileSearch className="h-10 w-10" />
          <p className="text-sm">Select a file to view its contents</p>
        </div>
      </div>
    )
  }

  const isBinary = fileContent?.is_binary || (fileInfo && !contentLoading && !fileContent)
  const isLoading = contentLoading && !fileContent && !fileInfo

  return (
    <div className="flex h-full flex-col">
      {/* File header bar */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-2">
        <span className="min-w-0 truncate font-mono text-sm">{selectedPath}</span>
        <div className="ml-auto flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
          {fileInfo && (
            <>
              <span>{fileInfo.mime_type}</span>
              <span>{formatFileSize(fileInfo.size)}</span>
              <span className="font-mono">{fileInfo.permissions}</span>
            </>
          )}
          {infoLoading && <Loader2 className="h-3 w-3 animate-spin" />}
        </div>
      </div>

      {/* Content area */}
      {isLoading ? (
        <div className="flex flex-1 items-center justify-center">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      ) : isBinary && projectId && fileInfo ? (
        <Tabs defaultValue="content" className="flex flex-1 flex-col overflow-hidden">
          <TabsList className="mx-4 mt-2 w-fit">
            <TabsTrigger value="content">Hex</TabsTrigger>
            <TabsTrigger value="info">Info</TabsTrigger>
          </TabsList>

          <TabsContent value="content" className="flex flex-1 flex-col overflow-hidden mt-0 p-0">
            <div className="flex-1 overflow-hidden">
              <HexViewer
                projectId={projectId}
                filePath={selectedPath}
                fileSize={fileInfo.size}
              />
            </div>
            {fileInfo.elf_info && (
              <div className="border-t border-border p-4">
                <BinaryInfo fileInfo={fileInfo} />
              </div>
            )}
          </TabsContent>

          <TabsContent value="info" className="flex-1 overflow-auto mt-0 p-4">
            <FileInfoPanel fileInfo={fileInfo} infoLoading={infoLoading} />
          </TabsContent>
        </Tabs>
      ) : fileContent ? (
        <Tabs defaultValue="content" className="flex flex-1 flex-col overflow-hidden">
          <TabsList className="mx-4 mt-2 w-fit">
            <TabsTrigger value="content">Content</TabsTrigger>
            <TabsTrigger value="info">Info</TabsTrigger>
          </TabsList>

          <TabsContent value="content" className="flex-1 overflow-hidden mt-0 p-0">
            <div className="flex h-full flex-col">
              {fileContent.truncated && (
                <div className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-yellow-500/30 bg-yellow-500/10 px-3 py-2 text-xs text-yellow-400">
                  <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
                  File content truncated. Only a portion of the file is shown.
                </div>
              )}
              <div className="flex-1">
                <Editor
                  language={getMonacoLanguage(selectedNode?.name ?? '')}
                  value={fileContent.content}
                  theme="vs-dark"
                  beforeMount={(monaco) => registerAssemblyLanguage(monaco)}
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    fontSize: 13,
                    lineNumbers: 'on',
                    wordWrap: 'on',
                    renderLineHighlight: 'none',
                    contextmenu: false,
                    automaticLayout: true,
                  }}
                />
              </div>
            </div>
          </TabsContent>

          <TabsContent value="info" className="flex-1 overflow-auto mt-0 p-4">
            <FileInfoPanel fileInfo={fileInfo} infoLoading={infoLoading} />
          </TabsContent>
        </Tabs>
      ) : (
        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
          Failed to load file content.
        </div>
      )}
    </div>
  )
}

function FileInfoPanel({
  fileInfo,
  infoLoading,
}: {
  fileInfo: import('@/types').FileInfo | null
  infoLoading: boolean
}) {
  if (fileInfo) {
    return (
      <div className="space-y-4">
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-2 text-sm">
          <dt className="text-muted-foreground">Path</dt>
          <dd className="font-mono break-all">{fileInfo.path}</dd>
          <dt className="text-muted-foreground">Type</dt>
          <dd>{fileInfo.type}</dd>
          <dt className="text-muted-foreground">MIME</dt>
          <dd>{fileInfo.mime_type}</dd>
          <dt className="text-muted-foreground">Size</dt>
          <dd>{formatFileSize(fileInfo.size)}</dd>
          <dt className="text-muted-foreground">Permissions</dt>
          <dd className="font-mono">{fileInfo.permissions}</dd>
          {fileInfo.sha256 && (
            <>
              <dt className="text-muted-foreground">SHA256</dt>
              <dd className="font-mono break-all">{fileInfo.sha256}</dd>
            </>
          )}
        </dl>
        {fileInfo.elf_info && <BinaryInfo fileInfo={fileInfo} />}
      </div>
    )
  }

  if (infoLoading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="h-5 w-5 animate-spin text-muted-foreground" />
      </div>
    )
  }

  return <p className="text-sm text-muted-foreground">File info unavailable.</p>
}
