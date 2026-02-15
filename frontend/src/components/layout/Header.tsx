import { useLocation } from 'react-router-dom'

const pageTitles: Record<string, string> = {
  '/projects': 'Projects',
}

export default function Header() {
  const { pathname } = useLocation()

  const title =
    pageTitles[pathname] ??
    (pathname.includes('/explore')
      ? 'File Explorer'
      : pathname.includes('/map')
        ? 'Component Map'
        : 'Project')

  return (
    <header className="flex h-14 shrink-0 items-center border-b border-border px-6">
      <h1 className="text-lg font-semibold">{title}</h1>
    </header>
  )
}
