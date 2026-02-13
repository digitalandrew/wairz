import { useParams, Link } from 'react-router-dom'
import { Button } from '@/components/ui/button'

export default function ProjectDetailPage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">
        Project <code className="rounded bg-muted px-1.5 py-0.5">{projectId}</code>
      </p>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" asChild>
          <Link to={`/projects/${projectId}/explore`}>
            Open File Explorer
          </Link>
        </Button>
      </div>
      <p className="text-muted-foreground">
        Full project detail view will be implemented in Session 2.2.
      </p>
    </div>
  )
}
