import { useEffect, useState } from 'react'
import { ChevronDown, ChevronRight, HardDrive, Loader2 } from 'lucide-react'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { getFirmwareMetadata } from '@/api/firmware'
import { formatFileSize } from '@/utils/format'
import type { FirmwareMetadata } from '@/types'

interface Props {
  projectId: string
  firmwareId: string
}

export default function FirmwareMetadataCard({ projectId, firmwareId }: Props) {
  const [metadata, setMetadata] = useState<FirmwareMetadata | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [envExpanded, setEnvExpanded] = useState(false)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setError(null)
    getFirmwareMetadata(projectId, firmwareId)
      .then((data) => {
        if (!cancelled) setMetadata(data)
      })
      .catch((e) => {
        if (!cancelled) setError(e?.response?.data?.detail || e.message || 'Failed to load metadata')
      })
      .finally(() => {
        if (!cancelled) setLoading(false)
      })
    return () => { cancelled = true }
  }, [projectId, firmwareId])

  if (loading) {
    return (
      <Card>
        <CardContent className="flex items-center gap-2 py-6 text-muted-foreground">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm">Loading firmware metadata...</span>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card>
        <CardContent className="py-4 text-sm text-muted-foreground">
          Could not load firmware metadata: {error}
        </CardContent>
      </Card>
    )
  }

  if (!metadata) return null

  const hasSections = metadata.sections.length > 0
  const hasUboot = !!metadata.uboot_header
  const hasEnv = Object.keys(metadata.uboot_env).length > 0
  const hasMtd = metadata.mtd_partitions.length > 0

  if (!hasSections && !hasUboot && !hasEnv && !hasMtd) return null

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-base">
          <HardDrive className="h-4 w-4" />
          Firmware Image Structure
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <p className="text-xs text-muted-foreground">
          Image size: {formatFileSize(metadata.file_size)}
        </p>

        {/* Sections table */}
        {hasSections && (
          <div>
            <h4 className="text-sm font-medium mb-2">Sections ({metadata.sections.length})</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-1 pr-4 font-medium">Offset</th>
                    <th className="pb-1 pr-4 font-medium">Size</th>
                    <th className="pb-1 font-medium">Type</th>
                  </tr>
                </thead>
                <tbody>
                  {metadata.sections.map((s, i) => (
                    <tr key={i} className="border-b border-border/50">
                      <td className="py-1 pr-4 font-mono">0x{s.offset.toString(16).toUpperCase().padStart(8, '0')}</td>
                      <td className="py-1 pr-4">{s.size != null ? formatFileSize(s.size) : '?'}</td>
                      <td className="py-1">
                        <Badge variant="outline" className="text-xs font-normal">
                          {s.type}
                        </Badge>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* U-Boot header */}
        {hasUboot && metadata.uboot_header && (
          <div>
            <h4 className="text-sm font-medium mb-2">U-Boot Header</h4>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-1 text-xs">
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Name:</dt>
                <dd className="font-medium">{metadata.uboot_header.name || '(empty)'}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">OS:</dt>
                <dd className="font-medium">{metadata.uboot_header.os_type}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Architecture:</dt>
                <dd className="font-medium">{metadata.uboot_header.architecture}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Image Type:</dt>
                <dd className="font-medium">{metadata.uboot_header.image_type}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Compression:</dt>
                <dd className="font-medium">{metadata.uboot_header.compression}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Data Size:</dt>
                <dd className="font-medium">{formatFileSize(metadata.uboot_header.data_size)}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Load Address:</dt>
                <dd className="font-mono font-medium">{metadata.uboot_header.load_address}</dd>
              </div>
              <div className="flex gap-1">
                <dt className="text-muted-foreground">Entry Point:</dt>
                <dd className="font-mono font-medium">{metadata.uboot_header.entry_point}</dd>
              </div>
            </dl>
          </div>
        )}

        {/* U-Boot env vars */}
        {hasEnv && (
          <div>
            <button
              onClick={() => setEnvExpanded(!envExpanded)}
              className="flex items-center gap-1 text-sm font-medium hover:text-foreground"
            >
              {envExpanded ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />}
              U-Boot Environment ({Object.keys(metadata.uboot_env).length} variables)
            </button>
            {envExpanded && (
              <pre className="mt-2 max-h-48 overflow-auto rounded bg-muted p-2 text-xs">
                {Object.entries(metadata.uboot_env)
                  .sort(([a], [b]) => a.localeCompare(b))
                  .map(([k, v]) => `${k}=${v}`)
                  .join('\n')}
              </pre>
            )}
          </div>
        )}

        {/* MTD partitions */}
        {hasMtd && (
          <div>
            <h4 className="text-sm font-medium mb-2">MTD Partitions ({metadata.mtd_partitions.length})</h4>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b text-left text-muted-foreground">
                    <th className="pb-1 pr-4 font-medium">Name</th>
                    <th className="pb-1 pr-4 font-medium">Offset</th>
                    <th className="pb-1 font-medium">Size</th>
                  </tr>
                </thead>
                <tbody>
                  {metadata.mtd_partitions.map((p, i) => (
                    <tr key={i} className="border-b border-border/50">
                      <td className="py-1 pr-4 font-medium">{p.name}</td>
                      <td className="py-1 pr-4 font-mono">
                        {p.offset != null ? `0x${p.offset.toString(16).toUpperCase().padStart(8, '0')}` : 'auto'}
                      </td>
                      <td className="py-1">{p.size === 0 ? '(rest)' : formatFileSize(p.size)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  )
}
