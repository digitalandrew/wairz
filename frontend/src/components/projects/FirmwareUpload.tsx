import { useCallback, useRef, useState } from 'react'
import { Upload, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { uploadFirmware as apiUploadFirmware, unpackFirmware as apiUnpackFirmware } from '@/api/firmware'
import { getProject } from '@/api/projects'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

type Phase = 'idle' | 'uploading' | 'done' | 'error'

interface FirmwareUploadProps {
  projectId: string
  onComplete?: () => void
  showVersionLabel?: boolean
}

export default function FirmwareUpload({ projectId, onComplete, showVersionLabel }: FirmwareUploadProps) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const [versionLabel, setVersionLabel] = useState('')
  const inputRef = useRef<HTMLInputElement>(null)

  const { uploadProgress } = useProjectStore()
  const setStore = useProjectStore.setState

  const handleFile = useCallback(
    async (file: File) => {
      setPhase('uploading')
      setErrorMsg('')
      try {
        setStore({ uploading: true, uploadProgress: 0 })
        const fw = await apiUploadFirmware(
          projectId,
          file,
          versionLabel || undefined,
          (pct) => setStore({ uploadProgress: pct }),
        )
        setStore({ uploading: false, uploadProgress: 100 })
        // Fire-and-forget: unpack returns 202 immediately, polling handles the rest
        apiUnpackFirmware(projectId, fw.id).catch(() => {})
        // Refresh project to pick up "unpacking" status
        const project = await getProject(projectId)
        setStore({ currentProject: project })
        setPhase('done')
        onComplete?.()
      } catch (e) {
        setStore({ uploading: false })
        setErrorMsg(e instanceof Error ? e.message : 'Upload failed')
        setPhase('error')
      }
    },
    [projectId, versionLabel, onComplete, setStore],
  )

  const onDrop = useCallback(
    (e: React.DragEvent) => {
      e.preventDefault()
      setDragActive(false)
      const file = e.dataTransfer.files[0]
      if (file) handleFile(file)
    },
    [handleFile],
  )

  const onInputChange = useCallback(
    (e: React.ChangeEvent<HTMLInputElement>) => {
      const file = e.target.files?.[0]
      if (file) handleFile(file)
    },
    [handleFile],
  )

  const retry = () => {
    setPhase('idle')
    setErrorMsg('')
  }

  if (phase === 'done') {
    return (
      <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed p-8">
        <CheckCircle className="h-8 w-8 text-green-500" />
        <p className="text-sm font-medium">Firmware uploaded — unpacking in progress</p>
      </div>
    )
  }

  if (phase === 'error') {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-destructive/50 p-8">
        <AlertCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm text-destructive">{errorMsg}</p>
        <Button size="sm" variant="outline" onClick={retry}>
          Try Again
        </Button>
      </div>
    )
  }

  if (phase === 'uploading') {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-8">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-sm font-medium">Uploading firmware...</p>
        <Progress value={uploadProgress} className="w-full max-w-xs" />
        <p className="text-xs text-muted-foreground">{uploadProgress}%</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {showVersionLabel && (
        <div className="space-y-1">
          <Label htmlFor="version-label" className="text-xs">Version Label (optional)</Label>
          <Input
            id="version-label"
            placeholder="e.g. v1.0, v1.1-patched"
            value={versionLabel}
            onChange={(e) => setVersionLabel(e.target.value)}
            className="h-8 text-sm"
          />
        </div>
      )}
      <div
        className={`flex cursor-pointer flex-col items-center gap-3 rounded-lg border-2 border-dashed p-8 transition-colors ${
          dragActive ? 'border-primary bg-primary/5' : 'border-muted-foreground/25 hover:border-muted-foreground/50'
        }`}
        onDragOver={(e) => {
          e.preventDefault()
          setDragActive(true)
        }}
        onDragLeave={() => setDragActive(false)}
        onDrop={onDrop}
        onClick={() => inputRef.current?.click()}
      >
        <Upload className="h-8 w-8 text-muted-foreground" />
        <div className="text-center">
          <p className="text-sm font-medium">Drop firmware file here or click to browse</p>
          <p className="text-xs text-muted-foreground mt-1">
            Supports .bin, .img, .hex, .chk, .trx, and other firmware formats
          </p>
        </div>
        <input ref={inputRef} type="file" className="hidden" onChange={onInputChange} />
      </div>
    </div>
  )
}
