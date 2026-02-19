import { useEffect, useState } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  ArrowLeft,
  Trash2,
  FolderSearch,
  ShieldAlert,
  Cpu,
  HardDrive,
  Hash,
  FileText,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { getFirmware } from '@/api/firmware'
import type { FirmwareDetail } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatFileSize, formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import DocumentsCard from '@/components/projects/DocumentsCard'
import AutonomousReviewCard from '@/components/projects/AutonomousReviewCard'
import McpConnectionCard from '@/components/projects/McpConnectionCard'

const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  ready: 'default',
  unpacking: 'secondary',
  error: 'destructive',
  created: 'outline',
}

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const {
    currentProject: project,
    loading,
    unpacking,
    fetchProject,
    removeProject,
    unpackFirmware,
    clearCurrentProject,
  } = useProjectStore()

  const [firmwareDetail, setFirmwareDetail] = useState<FirmwareDetail | null>(null)

  useEffect(() => {
    if (projectId) fetchProject(projectId)
    return () => clearCurrentProject()
  }, [projectId, fetchProject, clearCurrentProject])

  // Fetch full firmware detail (includes unpack_log) when project is in error state
  useEffect(() => {
    if (project?.status === 'error' && projectId) {
      getFirmware(projectId).then(setFirmwareDetail).catch(() => {})
    }
  }, [project?.status, projectId])

  if (loading || !project) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading project...</span>
      </div>
    )
  }

  const firmware = project.firmware?.[0] ?? null
  const status = project.status

  const handleDelete = async () => {
    if (window.confirm('Delete this project and all its data? This cannot be undone.')) {
      await removeProject(project.id)
      navigate('/projects')
    }
  }

  const handleUnpack = async () => {
    if (projectId) {
      try {
        await unpackFirmware(projectId)
      } catch {
        // error shown via store
      }
    }
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div className="space-y-1">
          <div className="flex items-center gap-3">
            <h1 className="text-2xl font-semibold tracking-tight">{project.name}</h1>
            <Badge
              variant={STATUS_VARIANT[status] ?? 'outline'}
              className={status === 'unpacking' ? 'animate-pulse' : ''}
            >
              {status}
            </Badge>
          </div>
          {project.description && (
            <p className="text-sm text-muted-foreground">{project.description}</p>
          )}
          <p className="text-xs text-muted-foreground">Created {formatDate(project.created_at)}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" asChild>
            <Link to="/projects">
              <ArrowLeft className="mr-2 h-4 w-4" />
              Back
            </Link>
          </Button>
          <Button variant="destructive" size="sm" onClick={handleDelete}>
            <Trash2 className="mr-2 h-4 w-4" />
            Delete
          </Button>
        </div>
      </div>

      {/* Firmware info */}
      {firmware && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Firmware</CardTitle>
          </CardHeader>
          <CardContent>
            <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
              <div className="flex items-center gap-2">
                <FileText className="h-4 w-4 text-muted-foreground" />
                <dt className="text-muted-foreground">File:</dt>
                <dd className="font-medium truncate">{firmware.original_filename}</dd>
              </div>
              <div className="flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-muted-foreground" />
                <dt className="text-muted-foreground">Size:</dt>
                <dd className="font-medium">
                  {firmware.file_size != null ? formatFileSize(firmware.file_size) : 'N/A'}
                </dd>
              </div>
              {firmware.architecture && (
                <div className="flex items-center gap-2">
                  <Cpu className="h-4 w-4 text-muted-foreground" />
                  <dt className="text-muted-foreground">Architecture:</dt>
                  <dd className="font-medium">
                    {firmware.architecture}
                    {firmware.endianness ? ` (${firmware.endianness})` : ''}
                  </dd>
                </div>
              )}
              <div className="flex items-center gap-2">
                <Hash className="h-4 w-4 text-muted-foreground" />
                <dt className="text-muted-foreground">SHA256:</dt>
                <dd className="font-mono text-xs truncate">{firmware.sha256}</dd>
              </div>
            </dl>
          </CardContent>
        </Card>
      )}

      {/* Project documents — always visible */}
      <DocumentsCard projectId={project.id} />

      {/* Action section based on status */}
      {status === 'created' && !firmware && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Upload Firmware</CardTitle>
          </CardHeader>
          <CardContent>
            <FirmwareUpload projectId={project.id} onComplete={() => fetchProject(project.id)} />
          </CardContent>
        </Card>
      )}

      {status === 'created' && firmware && (
        <Card>
          <CardContent className="flex items-center justify-between pt-6">
            <p className="text-sm text-muted-foreground">
              Firmware uploaded. Ready to unpack and analyze.
            </p>
            <Button size="sm" onClick={handleUnpack} disabled={unpacking}>
              {unpacking && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Unpack Firmware
            </Button>
          </CardContent>
        </Card>
      )}

      {status === 'ready' && (
        <>
          <div className="flex gap-3">
            <Button asChild>
              <Link to={`/projects/${project.id}/explore`}>
                <FolderSearch className="mr-2 h-4 w-4" />
                Explore Files
              </Link>
            </Button>
            <Button variant="outline" asChild>
              <Link to={`/projects/${project.id}/findings`}>
                <ShieldAlert className="mr-2 h-4 w-4" />
                Findings
              </Link>
            </Button>
          </div>

          <AutonomousReviewCard projectId={project.id} />

          <McpConnectionCard projectId={project.id} />
        </>
      )}

      {status === 'error' && (
        <Card className="border-destructive/50">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base text-destructive">
              <AlertCircle className="h-4 w-4" />
              Unpacking Failed
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            {firmwareDetail?.unpack_log && (
              <pre className="max-h-60 overflow-auto rounded bg-muted p-3 text-xs">
                {firmwareDetail.unpack_log}
              </pre>
            )}
            <Button size="sm" variant="outline" onClick={handleUnpack} disabled={unpacking}>
              {unpacking && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              Retry Unpack
            </Button>
          </CardContent>
        </Card>
      )}
    </div>
  )
}
