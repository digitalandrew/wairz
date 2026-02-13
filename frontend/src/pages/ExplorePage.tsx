import { useParams } from 'react-router-dom'

export default function ExplorePage() {
  const { projectId } = useParams<{ projectId: string }>()

  return (
    <div>
      <p className="text-muted-foreground">
        File explorer for project{' '}
        <code className="rounded bg-muted px-1.5 py-0.5">{projectId}</code>{' '}
        will be implemented in Session 2.3.
      </p>
    </div>
  )
}
