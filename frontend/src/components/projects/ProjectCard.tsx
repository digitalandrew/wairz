import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { MoreHorizontal, FolderOpen, Trash2, Download } from 'lucide-react'
import type { Project } from '@/types'
import { exportProject } from '@/api/exportImport'
import { Card, CardHeader, CardTitle, CardDescription, CardFooter } from '@/components/ui/card'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { formatDate } from '@/utils/format'

const STATUS_VARIANT: Record<string, 'default' | 'secondary' | 'destructive' | 'outline'> = {
  ready: 'default',
  unpacking: 'secondary',
  error: 'destructive',
  created: 'outline',
}

interface ProjectCardProps {
  project: Project
  onDelete: (id: string) => void
}

export default function ProjectCard({ project, onDelete }: ProjectCardProps) {
  const navigate = useNavigate()
  const [exporting, setExporting] = useState(false)
  const [exportError, setExportError] = useState<string | null>(null)

  const handleExport = async () => {
    setExporting(true)
    setExportError(null)
    try {
      const blob = await exportProject(project.id)
      const safeName = project.name.replace(/\s+/g, '_').replace(/\//g, '_')
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${safeName}.wairz`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      const msg = err instanceof Error
        ? err.message
        : 'Export failed'
      setExportError(msg)
    } finally {
      setExporting(false)
    }
  }

  return (
    <Card
      className="cursor-pointer transition-colors hover:border-foreground/20"
      onClick={() => navigate(`/projects/${project.id}`)}
    >
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <CardTitle className="text-base leading-snug">{project.name}</CardTitle>
          <DropdownMenu>
            <DropdownMenuTrigger asChild onClick={(e) => e.stopPropagation()}>
              <Button variant="ghost" size="icon-xs">
                <MoreHorizontal className="h-4 w-4" />
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end" onClick={(e) => e.stopPropagation()}>
              <DropdownMenuItem onClick={() => navigate(`/projects/${project.id}`)}>
                <FolderOpen className="mr-2 h-4 w-4" />
                Open
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleExport} disabled={exporting}>
                <Download className="mr-2 h-4 w-4" />
                {exporting ? 'Exporting...' : 'Export'}
              </DropdownMenuItem>
              <DropdownMenuItem
                variant="destructive"
                onClick={() => onDelete(project.id)}
              >
                <Trash2 className="mr-2 h-4 w-4" />
                Delete
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        </div>
        <CardDescription className="line-clamp-2">
          {project.description || 'No description'}
        </CardDescription>
        {exportError && (
          <div className="mt-2 rounded bg-destructive/10 border border-destructive/20 p-2 text-xs text-destructive">
            Export failed: {exportError}
          </div>
        )}
      </CardHeader>
      <CardFooter className="flex items-center justify-between pt-0">
        <Badge
          variant={STATUS_VARIANT[project.status] ?? 'outline'}
          className={project.status === 'unpacking' ? 'animate-pulse' : ''}
        >
          {project.status}
        </Badge>
        <span className="text-xs text-muted-foreground">{formatDate(project.created_at)}</span>
      </CardFooter>
    </Card>
  )
}
