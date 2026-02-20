import { useCallback, useRef, useState } from 'react'
import { Upload, CheckCircle, AlertCircle, Loader2 } from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { Progress } from '@/components/ui/progress'
import { Button } from '@/components/ui/button'

type Phase = 'idle' | 'uploading' | 'unpacking' | 'done' | 'error'

interface FirmwareUploadProps {
  projectId: string
  onComplete?: () => void
}

export default function FirmwareUpload({ projectId, onComplete }: FirmwareUploadProps) {
  const [phase, setPhase] = useState<Phase>('idle')
  const [errorMsg, setErrorMsg] = useState('')
  const [dragActive, setDragActive] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const { uploadFirmware, unpackFirmware, uploadProgress } = useProjectStore()

  const handleFile = useCallback(
    async (file: File) => {
      setPhase('uploading')
      setErrorMsg('')
      try {
        await uploadFirmware(projectId, file)
        setPhase('unpacking')
        await unpackFirmware(projectId)
        setPhase('done')
        onComplete?.()
      } catch (e) {
        setErrorMsg(e instanceof Error ? e.message : 'Upload failed')
        setPhase('error')
      }
    },
    [projectId, uploadFirmware, unpackFirmware, onComplete],
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
        <p className="text-sm font-medium">Firmware unpacked successfully</p>
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

  if (phase === 'unpacking') {
    return (
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed p-8">
        <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
        <p className="text-sm font-medium">Unpacking firmware...</p>
        <p className="text-xs text-muted-foreground">This may take a minute</p>
      </div>
    )
  }

  return (
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
  )
}
