import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Upload,
  Trash2,
  Loader2,
  ChevronDown,
  ChevronUp,
  HardDrive,
  AlertCircle,
  MessageSquare,
} from 'lucide-react'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Progress } from '@/components/ui/progress'
import { useChatStore } from '@/stores/chatStore'
import { listKernels, uploadKernel, deleteKernel } from '@/api/kernels'
import type { KernelInfo } from '@/types'

const SUPPORTED_ARCHITECTURES = ['arm', 'aarch64', 'mips', 'mipsel', 'x86', 'x86_64']

interface KernelManagerProps {
  firmwareArchitecture: string | null
  firmwareKernelPath: string | null
  onKernelSelect: (name: string | null) => void
  selectedKernel: string | null
  onRequestChat?: () => void
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

export default function KernelManager({
  firmwareArchitecture,
  firmwareKernelPath,
  onKernelSelect,
  selectedKernel,
  onRequestChat,
}: KernelManagerProps) {
  const setPendingMessage = useChatStore((s) => s.setPendingMessage)

  const [kernels, setKernels] = useState<KernelInfo[]>([])
  const [loading, setLoading] = useState(true)
  const [showUpload, setShowUpload] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Upload form state
  const [uploadName, setUploadName] = useState('')
  const [uploadArch, setUploadArch] = useState(firmwareArchitecture || 'arm')
  const [uploadDesc, setUploadDesc] = useState('')
  const [uploadFile, setUploadFile] = useState<File | null>(null)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [dragActive, setDragActive] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const fetchKernels = useCallback(async () => {
    try {
      const resp = await listKernels()
      setKernels(resp.kernels)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchKernels()
  }, [fetchKernels])

  // Update upload arch when firmware arch changes
  useEffect(() => {
    if (firmwareArchitecture) {
      setUploadArch(firmwareArchitecture)
    }
  }, [firmwareArchitecture])

  // Filter kernels matching firmware architecture
  const matchingKernels = firmwareArchitecture
    ? kernels.filter((k) => k.architecture === firmwareArchitecture)
    : kernels

  const handleUpload = async () => {
    if (!uploadFile || !uploadName.trim()) return

    setUploading(true)
    setError(null)
    setUploadProgress(0)

    try {
      await uploadKernel(
        uploadName.trim(),
        uploadArch,
        uploadDesc.trim(),
        uploadFile,
        (pct) => setUploadProgress(pct),
      )
      // Reset form
      setUploadName('')
      setUploadDesc('')
      setUploadFile(null)
      setShowUpload(false)
      setUploadProgress(0)
      await fetchKernels()
    } catch (err: unknown) {
      const resp = (err as { response?: { data?: { detail?: string } } }).response
      setError(resp?.data?.detail || (err instanceof Error ? err.message : 'Upload failed'))
    } finally {
      setUploading(false)
    }
  }

  const handleDelete = async (name: string) => {
    try {
      await deleteKernel(name)
      if (selectedKernel === name) {
        onKernelSelect(null)
      }
      await fetchKernels()
    } catch {
      // ignore
    }
  }

  const handleAskAI = useCallback(() => {
    const arch = firmwareArchitecture || 'the detected architecture'
    const prompt =
      `I need help finding a pre-built Linux kernel for system-mode emulation of this firmware. ` +
      `The firmware architecture is ${arch}. ` +
      `Please use the list_available_kernels tool to check what's currently available. ` +
      `If no matching kernel is found, find a suitable kernel from a trusted source ` +
      `and use the download_kernel tool to install it. Please explain your choice before downloading.`
    setPendingMessage(prompt)
    onRequestChat?.()
  }, [firmwareArchitecture, setPendingMessage, onRequestChat])

  const handleFileDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragActive(false)
    const file = e.dataTransfer.files[0]
    if (file) {
      setUploadFile(file)
      if (!uploadName.trim()) {
        setUploadName(file.name)
      }
    }
  }, [uploadName])

  if (loading) {
    return (
      <div className="flex items-center gap-2 py-2 text-xs text-muted-foreground">
        <Loader2 className="h-3 w-3 animate-spin" />
        Loading kernels...
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <label className="text-xs font-medium text-muted-foreground">Kernel</label>

      {/* Firmware-extracted kernel indicator */}
      {firmwareKernelPath && (
        <div className="flex items-start gap-2 rounded-md bg-yellow-500/10 px-3 py-2 text-xs text-yellow-600 dark:text-yellow-400">
          <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          <div>
            Kernel detected in firmware, but it may not be compatible with QEMU machine types.
            If system-mode emulation fails, upload a QEMU-compatible kernel below.
          </div>
        </div>
      )}

      {/* Kernel selector dropdown */}
      <select
        value={selectedKernel || ''}
        onChange={(e) => onKernelSelect(e.target.value || null)}
        className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
      >
        <option value="">{firmwareKernelPath ? 'Auto-select (firmware kernel)' : 'Auto-select'}</option>
        {matchingKernels.map((k) => (
          <option key={k.name} value={k.name}>
            {k.name} [{k.architecture}] ({formatSize(k.file_size)})
          </option>
        ))}
      </select>

      {/* Empty state — only show warning if no firmware kernel AND no uploaded kernels */}
      {matchingKernels.length === 0 && !firmwareKernelPath && (
        <div className="space-y-2">
          <div className="flex items-start gap-2 rounded-md bg-yellow-500/10 px-3 py-2 text-xs text-yellow-600 dark:text-yellow-400">
            <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
            <div>
              No kernels available{firmwareArchitecture ? ` for ${firmwareArchitecture}` : ''}.
              System-mode emulation requires a pre-built Linux kernel. Upload one below,
              or ask the AI assistant for help.
            </div>
          </div>
          <button
            onClick={handleAskAI}
            className="flex w-full items-center justify-center gap-1.5 rounded-md border border-primary/30 bg-primary/5 px-3 py-1.5 text-xs font-medium text-primary hover:bg-primary/10 transition-colors"
          >
            <MessageSquare className="h-3.5 w-3.5" />
            Get AI Help Finding a Kernel
          </button>
        </div>
      )}

      {/* Kernel list for matched arch */}
      {matchingKernels.length > 0 && (
        <div className="space-y-1">
          {matchingKernels.map((k) => (
            <div
              key={k.name}
              className="flex items-center justify-between rounded border border-border px-2 py-1.5"
            >
              <div className="flex items-center gap-2 min-w-0">
                <HardDrive className="h-3 w-3 shrink-0 text-muted-foreground" />
                <span className="truncate text-xs font-mono">{k.name}</span>
                <Badge variant="outline" className="text-[10px] shrink-0">
                  {k.architecture}
                </Badge>
                <span className="text-[10px] text-muted-foreground shrink-0">
                  {formatSize(k.file_size)}
                </span>
              </div>
              <button
                onClick={() => handleDelete(k.name)}
                className="ml-2 shrink-0 text-muted-foreground hover:text-destructive"
                title="Delete kernel"
              >
                <Trash2 className="h-3 w-3" />
              </button>
            </div>
          ))}
        </div>
      )}

      {/* Upload toggle */}
      <button
        onClick={() => setShowUpload(!showUpload)}
        className="flex items-center gap-1 text-xs text-primary hover:underline"
      >
        <Upload className="h-3 w-3" />
        Upload Kernel
        {showUpload ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
      </button>

      {/* Upload form */}
      {showUpload && (
        <div className="space-y-3 rounded-md border border-border p-3">
          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Name *
            </label>
            <input
              type="text"
              value={uploadName}
              onChange={(e) => setUploadName(e.target.value)}
              placeholder="vmlinux-arm-versatile"
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
            />
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Architecture *
            </label>
            <select
              value={uploadArch}
              onChange={(e) => setUploadArch(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none"
            >
              {SUPPORTED_ARCHITECTURES.map((arch) => (
                <option key={arch} value={arch}>
                  {arch}
                </option>
              ))}
            </select>
          </div>

          <div>
            <label className="mb-1 block text-xs font-medium text-muted-foreground">
              Description
            </label>
            <textarea
              value={uploadDesc}
              onChange={(e) => setUploadDesc(e.target.value)}
              placeholder="Linux 5.10 for ARM versatile-pb"
              rows={2}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-sm focus:border-primary focus:outline-none resize-none"
            />
          </div>

          {/* File drop zone */}
          <div
            onDrop={handleFileDrop}
            onDragOver={(e) => { e.preventDefault(); setDragActive(true) }}
            onDragLeave={() => setDragActive(false)}
            onClick={() => fileInputRef.current?.click()}
            className={`cursor-pointer rounded-md border-2 border-dashed p-4 text-center text-xs transition-colors ${
              dragActive
                ? 'border-primary bg-primary/5 text-primary'
                : uploadFile
                  ? 'border-green-500/50 bg-green-500/5 text-green-600'
                  : 'border-border text-muted-foreground hover:border-primary/50'
            }`}
          >
            <input
              ref={fileInputRef}
              type="file"
              className="hidden"
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file) {
                  setUploadFile(file)
                  if (!uploadName.trim()) setUploadName(file.name)
                }
              }}
            />
            {uploadFile ? (
              <div>
                <HardDrive className="mx-auto mb-1 h-5 w-5" />
                <p className="font-medium">{uploadFile.name}</p>
                <p className="text-muted-foreground">{formatSize(uploadFile.size)}</p>
              </div>
            ) : (
              <div>
                <Upload className="mx-auto mb-1 h-5 w-5" />
                <p>Drop kernel file here or click to browse</p>
              </div>
            )}
          </div>

          {uploading && (
            <Progress value={uploadProgress} className="h-1.5" />
          )}

          {error && (
            <div className="flex items-start gap-2 rounded-md bg-destructive/10 px-3 py-2 text-xs text-destructive">
              <AlertCircle className="mt-0.5 h-3.5 w-3.5 shrink-0" />
              {error}
            </div>
          )}

          <Button
            onClick={handleUpload}
            disabled={uploading || !uploadFile || !uploadName.trim()}
            size="sm"
            className="w-full"
          >
            {uploading ? (
              <Loader2 className="mr-1.5 h-3.5 w-3.5 animate-spin" />
            ) : (
              <Upload className="mr-1.5 h-3.5 w-3.5" />
            )}
            {uploading ? 'Uploading...' : 'Upload Kernel'}
          </Button>
        </div>
      )}
    </div>
  )
}
