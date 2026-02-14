import { useState, useEffect, useMemo, useCallback } from 'react'
import { Loader2, FileSearch, AlertTriangle, Search } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { useParams } from 'react-router-dom'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useExplorerStore } from '@/stores/explorerStore'
import { getMonacoLanguage } from '@/utils/fileIcons'
import { registerAssemblyLanguage } from '@/utils/monacoAssembly'
import { registerShellLanguage } from '@/utils/monacoShell'
import { formatFileSize } from '@/utils/format'
import { listFunctions, disassembleFunction, decompileFunction } from '@/api/analysis'
import type { FunctionInfo } from '@/types'
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
  const isElf = !!fileInfo?.elf_info
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
        <BinaryTabs
          projectId={projectId}
          filePath={selectedPath}
          fileInfo={fileInfo}
          isElf={isElf}
          infoLoading={infoLoading}
        />
      ) : fileContent ? (
        <TextTabs
          selectedNode={selectedNode}
          selectedPath={selectedPath}
          fileContent={fileContent}
          fileInfo={fileInfo}
          infoLoading={infoLoading}
        />
      ) : (
        <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
          Failed to load file content.
        </div>
      )}
    </div>
  )
}

/* ── Binary file tabs: Hex, Functions, Disassembly, Decompile, Info ── */

function BinaryTabs({
  projectId,
  filePath,
  fileInfo,
  isElf,
  infoLoading,
}: {
  projectId: string
  filePath: string
  fileInfo: import('@/types').FileInfo
  isElf: boolean
  infoLoading: boolean
}) {
  const [functions, setFunctions] = useState<FunctionInfo[]>([])
  const [functionsLoading, setFunctionsLoading] = useState(false)
  const [functionsLoaded, setFunctionsLoaded] = useState(false)
  const [selectedFunction, setSelectedFunction] = useState<string | null>(null)
  const [disasm, setDisasm] = useState<string | null>(null)
  const [disasmLoading, setDisasmLoading] = useState(false)
  const [decompilation, setDecompilation] = useState<string | null>(null)
  const [decompilationLoading, setDecompilationLoading] = useState(false)
  const [decompilationFunction, setDecompilationFunction] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('content')

  // Reset state when file changes
  useEffect(() => {
    setFunctions([])
    setFunctionsLoaded(false)
    setSelectedFunction(null)
    setDisasm(null)
    setDecompilation(null)
    setDecompilationFunction(null)
    setActiveTab('content')
  }, [filePath])

  // Load functions when Functions tab is first selected; load decompilation when Decompile tab selected
  const handleTabChange = useCallback(
    (tab: string) => {
      setActiveTab(tab)
      if (tab === 'functions' && !functionsLoaded && !functionsLoading && isElf) {
        setFunctionsLoading(true)
        listFunctions(projectId, filePath)
          .then((resp) => {
            setFunctions(resp.functions)
            setFunctionsLoaded(true)
          })
          .catch(() => setFunctions([]))
          .finally(() => setFunctionsLoading(false))
      }
      if (tab === 'decompile' && selectedFunction && decompilationFunction !== selectedFunction) {
        setDecompilation(null)
        setDecompilationFunction(selectedFunction)
        setDecompilationLoading(true)
        decompileFunction(projectId, filePath, selectedFunction)
          .then((resp) => setDecompilation(resp.decompiled_code))
          .catch(() => setDecompilation('Decompilation failed.'))
          .finally(() => setDecompilationLoading(false))
      }
    },
    [projectId, filePath, functionsLoaded, functionsLoading, isElf, selectedFunction, decompilationFunction],
  )

  // Load disassembly when a function is selected
  const handleSelectFunction = useCallback(
    (funcName: string) => {
      setSelectedFunction(funcName)
      setDisasm(null)
      setDisasmLoading(true)
      setActiveTab('disasm')
      disassembleFunction(projectId, filePath, funcName)
        .then((resp) => setDisasm(resp.disassembly))
        .catch(() => setDisasm('Failed to disassemble function.'))
        .finally(() => setDisasmLoading(false))
    },
    [projectId, filePath],
  )

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange} className="flex flex-1 flex-col overflow-hidden">
      <TabsList className="mx-4 mt-2 w-fit">
        <TabsTrigger value="content">Hex</TabsTrigger>
        {isElf && <TabsTrigger value="functions">Functions</TabsTrigger>}
        {isElf && selectedFunction && <TabsTrigger value="disasm">Disassembly</TabsTrigger>}
        {isElf && selectedFunction && <TabsTrigger value="decompile">Decompile</TabsTrigger>}
        <TabsTrigger value="info">Info</TabsTrigger>
      </TabsList>

      <TabsContent value="content" className="flex flex-1 flex-col overflow-hidden mt-0 p-0">
        <div className="flex-1 overflow-hidden">
          <HexViewer projectId={projectId} filePath={filePath} fileSize={fileInfo.size} />
        </div>
        {fileInfo.elf_info && (
          <div className="border-t border-border p-4">
            <BinaryInfo fileInfo={fileInfo} />
          </div>
        )}
      </TabsContent>

      {isElf && (
        <TabsContent value="functions" className="flex-1 overflow-hidden mt-0 p-0">
          <FunctionListPanel
            functions={functions}
            loading={functionsLoading}
            selectedFunction={selectedFunction}
            onSelectFunction={handleSelectFunction}
          />
        </TabsContent>
      )}

      {isElf && selectedFunction && (
        <TabsContent value="disasm" className="flex-1 overflow-hidden mt-0 p-0">
          <DisassemblyPanel
            functionName={selectedFunction}
            disassembly={disasm}
            loading={disasmLoading}
          />
        </TabsContent>
      )}

      {isElf && selectedFunction && (
        <TabsContent value="decompile" className="flex-1 overflow-hidden mt-0 p-0">
          <DecompilationPanel
            functionName={selectedFunction}
            decompilation={decompilation}
            loading={decompilationLoading}
          />
        </TabsContent>
      )}

      <TabsContent value="info" className="flex-1 overflow-auto mt-0 p-4">
        <FileInfoPanel fileInfo={fileInfo} infoLoading={infoLoading} />
      </TabsContent>
    </Tabs>
  )
}

/* ── Function list panel with search ── */

function FunctionListPanel({
  functions,
  loading,
  selectedFunction,
  onSelectFunction,
}: {
  functions: FunctionInfo[]
  loading: boolean
  selectedFunction: string | null
  onSelectFunction: (name: string) => void
}) {
  const [filter, setFilter] = useState('')

  const filtered = useMemo(() => {
    if (!filter) return functions
    const lower = filter.toLowerCase()
    return functions.filter((f) => f.name.toLowerCase().includes(lower))
  }, [functions, filter])

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Analyzing binary (this may take 10-30s)…</span>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      {/* Search bar */}
      <div className="flex items-center gap-2 border-b border-border px-4 py-2">
        <Search className="h-4 w-4 text-muted-foreground" />
        <input
          type="text"
          placeholder="Filter functions…"
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
        />
        <span className="text-xs text-muted-foreground">
          {filtered.length} / {functions.length}
        </span>
      </div>

      {/* Function list */}
      <div className="flex-1 overflow-auto">
        {filtered.length === 0 ? (
          <div className="p-4 text-center text-sm text-muted-foreground">
            {functions.length === 0 ? 'No functions found.' : 'No matches.'}
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-background">
              <tr className="border-b border-border text-left text-muted-foreground">
                <th className="px-4 py-1.5 font-medium">Function</th>
                <th className="px-4 py-1.5 font-medium text-right">Size</th>
                <th className="px-4 py-1.5 font-medium text-right">Address</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((fn) => (
                <tr
                  key={fn.name}
                  onClick={() => onSelectFunction(fn.name)}
                  className={`cursor-pointer border-b border-border/50 ${
                    fn.name === selectedFunction
                      ? 'bg-accent text-accent-foreground'
                      : 'hover:bg-accent/50'
                  }`}
                >
                  <td className="px-4 py-1.5 font-mono">{fn.name}</td>
                  <td className="px-4 py-1.5 text-right text-muted-foreground">
                    {fn.size} B
                  </td>
                  <td className="px-4 py-1.5 text-right font-mono text-muted-foreground">
                    0x{fn.offset.toString(16).padStart(8, '0')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

/* ── Disassembly display in Monaco ── */

function DisassemblyPanel({
  functionName,
  disassembly,
  loading,
}: {
  functionName: string
  disassembly: string | null
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Disassembling {functionName}…</span>
        </div>
      </div>
    )
  }

  if (!disassembly) {
    return (
      <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
        No disassembly available.
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-border px-4 py-1.5 text-xs text-muted-foreground">
        Disassembly of <span className="font-mono text-foreground">{functionName}</span>
      </div>
      <div className="flex-1">
        <Editor
          language="assembly"
          value={disassembly}
          theme="vs-dark"
          beforeMount={(monaco) => {
            registerAssemblyLanguage(monaco)
          }}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontSize: 13,
            lineNumbers: 'on',
            wordWrap: 'off',
            renderLineHighlight: 'none',
            contextmenu: false,
            automaticLayout: true,
          }}
        />
      </div>
    </div>
  )
}

/* ── Decompilation (pseudo-C) display in Monaco ── */

function DecompilationPanel({
  functionName,
  decompilation,
  loading,
}: {
  functionName: string
  decompilation: string | null
  loading: boolean
}) {
  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Decompiling {functionName}… (this may take 30–120s on first call)</span>
        </div>
      </div>
    )
  }

  if (!decompilation) {
    return (
      <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
        Decompilation unavailable.
      </div>
    )
  }

  return (
    <div className="flex h-full flex-col">
      <div className="border-b border-border px-4 py-1.5 text-xs text-muted-foreground">
        Decompilation of <span className="font-mono text-foreground">{functionName}</span>
      </div>
      <div className="flex-1">
        <Editor
          language="c"
          value={decompilation}
          theme="vs-dark"
          options={{
            readOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            fontSize: 13,
            lineNumbers: 'on',
            wordWrap: 'off',
            renderLineHighlight: 'none',
            contextmenu: false,
            automaticLayout: true,
          }}
        />
      </div>
    </div>
  )
}

/* ── Text file tabs: Content, Info ── */

function TextTabs({
  selectedNode,
  fileContent,
  fileInfo,
  infoLoading,
}: {
  selectedNode: import('@/stores/explorerStore').TreeNode | null
  selectedPath: string
  fileContent: import('@/types').FileContent
  fileInfo: import('@/types').FileInfo | null
  infoLoading: boolean
}) {
  return (
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
              language={getMonacoLanguage(selectedNode?.name ?? '', fileContent.content)}
              value={fileContent.content}
              theme="vs-dark"
              beforeMount={(monaco) => {
                registerAssemblyLanguage(monaco)
                registerShellLanguage(monaco)
              }}
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
  )
}

/* ── File info panel (shared) ── */

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
