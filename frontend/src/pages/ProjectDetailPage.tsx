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
  GitCompareArrows,
  Plus,
  Tag,
} from 'lucide-react'
import { useProjectStore } from '@/stores/projectStore'
import { listFirmware, deleteFirmware } from '@/api/firmware'
import type { FirmwareDetail } from '@/types'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { formatFileSize, formatDate } from '@/utils/format'
import FirmwareUpload from '@/components/projects/FirmwareUpload'
import FirmwareMetadataCard from '@/components/projects/FirmwareMetadataCard'
import DocumentsCard from '@/components/projects/DocumentsCard'
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

  const [firmwareList, setFirmwareList] = useState<FirmwareDetail[]>([])
  const [showUpload, setShowUpload] = useState(false)

  useEffect(() => {
    if (projectId) fetchProject(projectId)
    return () => clearCurrentProject()
  }, [projectId, fetchProject, clearCurrentProject])

  // Fetch full firmware list for details (includes unpack_log, extracted_path)
  useEffect(() => {
    if (projectId && project) {
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    }
  }, [project, projectId])

  if (loading || !project) {
    return (
      <div className="flex items-center gap-2 py-12 justify-center text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span>Loading project...</span>
      </div>
    )
  }

  const firmware = project.firmware ?? []
  const status = project.status
  const hasUnpacked = firmwareList.some((fw) => fw.extracted_path)
  const unpackedCount = firmwareList.filter((fw) => fw.extracted_path).length

  const handleDelete = async () => {
    if (window.confirm('Delete this project and all its data? This cannot be undone.')) {
      await removeProject(project.id)
      navigate('/projects')
    }
  }

  const handleUnpack = async (firmwareId: string) => {
    if (projectId) {
      try {
        await unpackFirmware(projectId, firmwareId)
        // Refresh firmware list
        listFirmware(projectId).then(setFirmwareList).catch(() => {})
      } catch {
        // error shown via store
      }
    }
  }

  const handleDeleteFirmware = async (firmwareId: string) => {
    if (!projectId) return
    if (!window.confirm('Delete this firmware version? This cannot be undone.')) return
    try {
      await deleteFirmware(projectId, firmwareId)
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
    } catch {
      // error handled by caller
    }
  }

  const handleUploadComplete = () => {
    setShowUpload(false)
    if (projectId) {
      fetchProject(projectId)
      listFirmware(projectId).then(setFirmwareList).catch(() => {})
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

      {/* Firmware cards */}
      {firmware.length > 0 && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h2 className="text-sm font-semibold uppercase tracking-wide text-muted-foreground">
              Firmware ({firmware.length})
            </h2>
            <Button size="sm" variant="outline" onClick={() => setShowUpload(!showUpload)}>
              <Plus className="mr-1 h-3.5 w-3.5" />
              Upload Version
            </Button>
          </div>

          {firmware.map((fw) => {
            const fwDetail = firmwareList.find((f) => f.id === fw.id)
            const isUnpacked = fwDetail?.extracted_path
            const hasError = fwDetail?.unpack_log && !isUnpacked && status === 'error'

            return (
              <Card key={fw.id}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      {fw.original_filename}
                      {fw.version_label && (
                        <Badge variant="secondary" className="text-xs">
                          <Tag className="mr-1 h-3 w-3" />
                          {fw.version_label}
                        </Badge>
                      )}
                      {isUnpacked && (
                        <Badge variant="default" className="text-xs">unpacked</Badge>
                      )}
                    </CardTitle>
                    <div className="flex gap-1">
                      {!isUnpacked && !hasError && (
                        <Button size="sm" onClick={() => handleUnpack(fw.id)} disabled={unpacking}>
                          {unpacking && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                          Unpack
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="ghost"
                        className="text-destructive hover:text-destructive"
                        onClick={() => handleDeleteFirmware(fw.id)}
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  </div>
                </CardHeader>
                <CardContent>
                  <dl className="grid grid-cols-1 gap-3 text-sm sm:grid-cols-2">
                    <div className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">Size:</dt>
                      <dd className="font-medium">
                        {fw.file_size != null ? formatFileSize(fw.file_size) : 'N/A'}
                      </dd>
                    </div>
                    {fw.architecture && (
                      <div className="flex items-center gap-2">
                        <Cpu className="h-4 w-4 text-muted-foreground" />
                        <dt className="text-muted-foreground">Architecture:</dt>
                        <dd className="font-medium">
                          {fw.architecture}
                          {fw.endianness ? ` (${fw.endianness})` : ''}
                        </dd>
                      </div>
                    )}
                    <div className="flex items-center gap-2 col-span-2">
                      <Hash className="h-4 w-4 text-muted-foreground" />
                      <dt className="text-muted-foreground">SHA256:</dt>
                      <dd className="font-mono text-xs truncate">{fw.sha256}</dd>
                    </div>
                  </dl>

                  {hasError && fwDetail?.unpack_log && (
                    <div className="mt-3 rounded bg-destructive/5 border border-destructive/20 p-3">
                      <div className="flex items-center gap-2 text-sm text-destructive mb-2">
                        <AlertCircle className="h-4 w-4" />
                        Unpacking Failed
                      </div>
                      <pre className="max-h-40 overflow-auto text-xs">{fwDetail.unpack_log}</pre>
                      <Button
                        size="sm"
                        variant="outline"
                        className="mt-2"
                        onClick={() => handleUnpack(fw.id)}
                        disabled={unpacking}
                      >
                        {unpacking && <Loader2 className="mr-2 h-3.5 w-3.5 animate-spin" />}
                        Retry
                      </Button>
                    </div>
                  )}
                </CardContent>
              </Card>
            )
          })}
        </div>
      )}

      {/* Upload section */}
      {(showUpload || (status === 'created' && firmware.length === 0)) && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Upload Firmware</CardTitle>
          </CardHeader>
          <CardContent>
            <FirmwareUpload
              projectId={project.id}
              onComplete={handleUploadComplete}
              showVersionLabel={firmware.length > 0}
            />
          </CardContent>
        </Card>
      )}

      {/* Project documents */}
      <DocumentsCard projectId={project.id} />

      {/* Firmware metadata cards for unpacked firmware */}
      {firmwareList
        .filter((fw) => fw.extracted_path)
        .map((fw) => (
          <FirmwareMetadataCard key={fw.id} projectId={project.id} firmwareId={fw.id} />
        ))}

      {/* Action buttons when ready */}
      {hasUnpacked && (
        <>
          <div className="flex gap-3 flex-wrap">
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
            {unpackedCount >= 2 && (
              <Button variant="outline" asChild>
                <Link to={`/projects/${project.id}/compare`}>
                  <GitCompareArrows className="mr-2 h-4 w-4" />
                  Compare Versions
                </Link>
              </Button>
            )}
          </div>

          <McpConnectionCard projectId={project.id} />
        </>
      )}
    </div>
  )
}
