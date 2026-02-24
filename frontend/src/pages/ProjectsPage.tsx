import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Plus, Upload, Loader2 } from 'lucide-react'
import { Button } from '@/components/ui/button'
import ProjectList from '@/components/projects/ProjectList'
import CreateProjectDialog from '@/components/projects/CreateProjectDialog'
import { importProject } from '@/api/exportImport'
import { useProjectStore } from '@/stores/projectStore'

export default function ProjectsPage() {
  const [dialogOpen, setDialogOpen] = useState(false)
  const [importing, setImporting] = useState(false)
  const [importError, setImportError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const navigate = useNavigate()
  const fetchProjects = useProjectStore((s) => s.fetchProjects)

  const handleImportClick = () => {
    fileInputRef.current?.click()
  }

  const handleFileSelected = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return
    // Reset file input so the same file can be selected again
    e.target.value = ''

    setImporting(true)
    setImportError(null)
    try {
      const project = await importProject(file)
      await fetchProjects()
      navigate(`/projects/${project.id}`)
    } catch (err) {
      const msg =
        err && typeof err === 'object' && 'response' in err
          ? (err as { response?: { data?: { detail?: string } } }).response?.data?.detail
          : err instanceof Error
            ? err.message
            : 'Import failed'
      setImportError(msg ?? 'Import failed')
    } finally {
      setImporting(false)
    }
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-semibold tracking-tight">Projects</h1>
        <div className="flex gap-2">
          <Button size="sm" variant="outline" onClick={handleImportClick} disabled={importing}>
            {importing ? (
              <Loader2 className="mr-2 h-4 w-4 animate-spin" />
            ) : (
              <Upload className="mr-2 h-4 w-4" />
            )}
            Import
          </Button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".wairz,.zip"
            className="hidden"
            onChange={handleFileSelected}
          />
          <Button size="sm" onClick={() => setDialogOpen(true)}>
            <Plus className="mr-2 h-4 w-4" />
            New Project
          </Button>
        </div>
      </div>

      {importError && (
        <div className="rounded bg-destructive/10 border border-destructive/20 p-3 text-sm text-destructive">
          {importError}
        </div>
      )}

      <ProjectList onCreateClick={() => setDialogOpen(true)} />
      <CreateProjectDialog open={dialogOpen} onOpenChange={setDialogOpen} />
    </div>
  )
}
