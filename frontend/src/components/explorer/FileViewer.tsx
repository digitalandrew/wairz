import { useState, useEffect, useMemo, useCallback, useRef } from 'react'
import { Loader2, FileSearch, AlertTriangle, Search, Save, Sparkles } from 'lucide-react'
import Editor from '@monaco-editor/react'
import { useParams } from 'react-router-dom'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'
import { useExplorerStore } from '@/stores/explorerStore'
import { getMonacoLanguage } from '@/utils/fileIcons'
import { registerAssemblyLanguage } from '@/utils/monacoAssembly'
import { registerShellLanguage } from '@/utils/monacoShell'
import { formatFileSize } from '@/utils/format'
import { listFunctions, listImports, disassembleFunction, decompileFunction, cleanupCode } from '@/api/analysis'
import type { FunctionInfo, ImportInfo } from '@/types'
import HexViewer from './HexViewer'
import BinaryInfo from './BinaryInfo'

/** Map document filename extension to Monaco language */
function getDocumentLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase()
  switch (ext) {
    case 'md':
      return 'markdown'
    case 'json':
      return 'json'
    case 'xml':
    case 'html':
      return 'html'
    case 'csv':
    case 'txt':
    default:
      return 'plaintext'
  }
}

const EDITABLE_EXTENSIONS = new Set(['.md', '.txt', '.json', '.xml', '.html', '.csv'])

function isDocumentEditable(filename: string): boolean {
  const dot = filename.lastIndexOf('.')
  if (dot === -1) return false
  return EDITABLE_EXTENSIONS.has(filename.slice(dot).toLowerCase())
}

export default function FileViewer() {
  const { projectId } = useParams<{ projectId: string }>()
  const {
    selectedNode, selectedPath, selectedDocumentId, documents,
    fileContent, fileInfo, contentLoading, infoLoading,
    documentDirty, documentContent, setDocumentContent, saveDocument,
  } = useExplorerStore()

  const saveRef = useRef<(() => void) | null>(null)

  // Document view mode
  if (selectedDocumentId) {
    const doc = documents.find((d) => d.id === selectedDocumentId)
    const filename = doc?.original_filename ?? 'Document'
    const editable = isDocumentEditable(filename)
    const displayContent = documentContent !== null ? documentContent : (fileContent?.content ?? '')

    // Keep saveRef current for Ctrl+S keybinding
    saveRef.current = () => {
      if (projectId && documentDirty) saveDocument(projectId)
    }

    return (
      <div className="flex h-full flex-col">
        {/* Document header bar */}
        <div className="flex items-center gap-3 border-b border-border px-4 py-2">
          <span className="min-w-0 truncate font-mono text-sm">{filename}</span>
          {documentDirty && (
            <span className="h-2 w-2 shrink-0 rounded-full bg-blue-400" title="Unsaved changes" />
          )}
          <div className="ml-auto flex shrink-0 items-center gap-3 text-xs text-muted-foreground">
            {doc && (
              <>
                <span>{doc.content_type}</span>
                <span>{formatFileSize(doc.file_size)}</span>
              </>
            )}
            {editable && (
              <button
                onClick={() => projectId && saveDocument(projectId)}
                disabled={!documentDirty}
                className="flex items-center gap-1 rounded px-2 py-1 text-xs hover:bg-accent hover:text-accent-foreground disabled:opacity-40"
                title="Save (Ctrl+S)"
              >
                <Save className="h-3.5 w-3.5" />
                Save
              </button>
            )}
          </div>
        </div>

        {/* Document content */}
        {contentLoading ? (
          <div className="flex flex-1 items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : fileContent ? (
          <div className="flex-1">
            <Editor
              language={getDocumentLanguage(filename)}
              value={displayContent}
              theme="vs-dark"
              onChange={(value) => {
                if (editable && value !== undefined) {
                  setDocumentContent(value)
                }
              }}
              onMount={(editor, monaco) => {
                if (editable) {
                  editor.addAction({
                    id: 'save-document',
                    label: 'Save Document',
                    keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS],
                    run: () => { saveRef.current?.() },
                  })
                }
              }}
              options={{
                readOnly: !editable,
                minimap: { enabled: false },
                scrollBeyondLastLine: false,
                fontSize: 13,
                lineNumbers: 'on',
                wordWrap: 'on',
                renderLineHighlight: editable ? 'line' : 'none',
                contextmenu: false,
                automaticLayout: true,
              }}
            />
          </div>
        ) : (
          <div className="flex flex-1 items-center justify-center text-sm text-muted-foreground">
            Failed to load document content.
          </div>
        )}
      </div>
    )
  }

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
  const [imports, setImports] = useState<ImportInfo[]>([])
  const [functionsLoading, setFunctionsLoading] = useState(false)
  const [functionsLoaded, setFunctionsLoaded] = useState(false)
  const [selectedFunction, setSelectedFunction] = useState<string | null>(null)
  const [disasm, setDisasm] = useState<string | null>(null)
  const [disasmLoading, setDisasmLoading] = useState(false)
  const [decompilation, setDecompilation] = useState<string | null>(null)
  const [decompilationLoading, setDecompilationLoading] = useState(false)
  const [decompilationFunction, setDecompilationFunction] = useState<string | null>(null)
  const [cleanedCode, setCleanedCode] = useState<string | null>(null)
  const [cleanupLoading, setCleanupLoading] = useState(false)
  const [cleanupError, setCleanupError] = useState<string | null>(null)
  const [cleanupFunction, setCleanupFunction] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('content')

  // Reset state when file changes
  useEffect(() => {
    setFunctions([])
    setImports([])
    setFunctionsLoaded(false)
    setSelectedFunction(null)
    setDisasm(null)
    setDecompilation(null)
    setDecompilationFunction(null)
    setCleanedCode(null)
    setCleanupError(null)
    setCleanupFunction(null)
    setActiveTab('content')
  }, [filePath])

  // Load functions when Functions tab is first selected; load decompilation when Decompile tab selected
  const handleTabChange = useCallback(
    (tab: string) => {
      setActiveTab(tab)
      if (tab === 'functions' && !functionsLoaded && !functionsLoading && isElf) {
        setFunctionsLoading(true)
        Promise.all([
          listFunctions(projectId, filePath),
          listImports(projectId, filePath).catch(() => ({ imports: [] as ImportInfo[] })),
        ])
          .then(([funcResp, impResp]) => {
            setFunctions(funcResp.functions)
            setImports(impResp.imports)
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

  // Request AI cleanup for the current decompilation
  const handleCleanup = useCallback(
    (funcName: string) => {
      if (cleanupLoading) return
      setCleanupLoading(true)
      setCleanupError(null)
      cleanupCode(projectId, filePath, funcName)
        .then((resp) => {
          setCleanedCode(resp.cleaned_code)
          setCleanupFunction(funcName)
        })
        .catch(() => setCleanupError('AI cleanup failed. Please try again.'))
        .finally(() => setCleanupLoading(false))
    },
    [projectId, filePath, cleanupLoading],
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
            imports={imports}
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
            cleanedCode={cleanupFunction === selectedFunction ? cleanedCode : null}
            cleanupLoading={cleanupLoading}
            cleanupError={cleanupError}
            onCleanup={() => handleCleanup(selectedFunction)}
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
  imports,
  loading,
  selectedFunction,
  onSelectFunction,
}: {
  functions: FunctionInfo[]
  imports: ImportInfo[]
  loading: boolean
  selectedFunction: string | null
  onSelectFunction: (name: string) => void
}) {
  const [filter, setFilter] = useState('')

  // Build a lookup: function name → library name from imports
  const importMap = useMemo(() => {
    const map = new Map<string, string>()
    for (const imp of imports) {
      if (imp.name && imp.libname) {
        map.set(imp.name, imp.libname)
      }
    }
    return map
  }, [imports])

  const filtered = useMemo(() => {
    if (!filter) return functions
    const lower = filter.toLowerCase()
    return functions.filter((f) => {
      if (f.name.toLowerCase().includes(lower)) return true
      // Also match on library name
      const lib = importMap.get(f.name)
      if (lib && lib.toLowerCase().includes(lower)) return true
      return false
    })
  }, [functions, filter, importMap])

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
                <th className="px-4 py-1.5 font-medium">Imported From</th>
                <th className="px-4 py-1.5 font-medium text-right">Size</th>
                <th className="px-4 py-1.5 font-medium text-right">Address</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map((fn) => {
                const lib = importMap.get(fn.name)
                return (
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
                    <td className="px-4 py-1.5 font-mono text-muted-foreground">
                      {lib ?? ''}
                    </td>
                    <td className="px-4 py-1.5 text-right text-muted-foreground">
                      {fn.size} B
                    </td>
                    <td className="px-4 py-1.5 text-right font-mono text-muted-foreground">
                      0x{fn.offset.toString(16).padStart(8, '0')}
                    </td>
                  </tr>
                )
              })}
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

/* ── Decompilation (pseudo-C) display in Monaco with AI cleanup ── */

function DecompilationPanel({
  functionName,
  decompilation,
  loading,
  cleanedCode,
  cleanupLoading,
  cleanupError,
  onCleanup,
}: {
  functionName: string
  decompilation: string | null
  loading: boolean
  cleanedCode: string | null
  cleanupLoading: boolean
  cleanupError: string | null
  onCleanup: () => void
}) {
  const [viewMode, setViewMode] = useState<'raw' | 'cleaned'>('raw')

  // Switch to cleaned view when cleanup completes
  useEffect(() => {
    if (cleanedCode) setViewMode('cleaned')
  }, [cleanedCode])

  // Reset to raw when function changes
  useEffect(() => {
    setViewMode('raw')
  }, [functionName])

  if (loading) {
    return (
      <div className="flex flex-1 items-center justify-center">
        <div className="flex flex-col items-center gap-2 text-muted-foreground">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-xs">Decompiling {functionName}… (this may take 30-120s on first call)</span>
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

  const showingCleaned = viewMode === 'cleaned' && cleanedCode
  const displayCode = showingCleaned ? cleanedCode : decompilation

  return (
    <div className="flex h-full flex-col">
      {/* Header with view toggle and cleanup button */}
      <div className="flex items-center gap-3 border-b border-border px-4 py-1.5">
        <span className="text-xs text-muted-foreground">
          Decompilation of <span className="font-mono text-foreground">{functionName}</span>
        </span>

        {showingCleaned && (
          <span className="rounded-full bg-violet-500/15 px-2 py-0.5 text-[10px] font-medium text-violet-400">
            AI Cleaned
          </span>
        )}

        <div className="ml-auto flex items-center gap-2">
          {/* Raw / Cleaned toggle — only show when cleaned code is available */}
          {cleanedCode && (
            <div className="flex rounded-md border border-border text-[11px]">
              <button
                onClick={() => setViewMode('raw')}
                className={`px-2 py-0.5 transition-colors ${
                  viewMode === 'raw'
                    ? 'bg-accent text-accent-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Raw
              </button>
              <button
                onClick={() => setViewMode('cleaned')}
                className={`px-2 py-0.5 transition-colors ${
                  viewMode === 'cleaned'
                    ? 'bg-accent text-accent-foreground'
                    : 'text-muted-foreground hover:text-foreground'
                }`}
              >
                Cleaned
              </button>
            </div>
          )}

          {/* Clean Up with AI button */}
          {!cleanedCode && (
            <button
              onClick={onCleanup}
              disabled={cleanupLoading}
              className="flex items-center gap-1.5 rounded-md border border-violet-500/30 bg-violet-500/10 px-2.5 py-1 text-[11px] font-medium text-violet-400 transition-colors hover:bg-violet-500/20 disabled:opacity-50"
            >
              {cleanupLoading ? (
                <Loader2 className="h-3 w-3 animate-spin" />
              ) : (
                <Sparkles className="h-3 w-3" />
              )}
              {cleanupLoading ? 'Cleaning up…' : 'Clean Up with AI'}
            </button>
          )}
        </div>
      </div>

      {/* Error banner */}
      {cleanupError && (
        <div className="mx-4 mt-2 flex items-center gap-2 rounded-md border border-red-500/30 bg-red-500/10 px-3 py-2 text-xs text-red-400">
          <AlertTriangle className="h-3.5 w-3.5 shrink-0" />
          {cleanupError}
        </div>
      )}

      {/* Code editor */}
      <div className="flex-1">
        <Editor
          language="c"
          value={displayCode}
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
