import { useEffect, useState } from 'react'
import { NavLink, useParams, useNavigate } from 'react-router-dom'
import {
  Shield,
  PanelLeftClose,
  PanelLeftOpen,
  FolderOpen,
  ChevronRight,
  LayoutDashboard,
  FolderSearch,
  ShieldAlert,
  HelpCircle,
} from 'lucide-react'
import { Separator } from '@/components/ui/separator'
import { useProjectStore } from '@/stores/projectStore'

interface SidebarProps {
  collapsed: boolean
  onToggle: () => void
}

const projectSubPages = [
  { suffix: '', label: 'Overview', icon: LayoutDashboard },
  { suffix: '/explore', label: 'File Explorer', icon: FolderSearch },
  { suffix: '/findings', label: 'Findings', icon: ShieldAlert },
]

export default function Sidebar({ collapsed, onToggle }: SidebarProps) {
  const { projectId: activeProjectId } = useParams<{ projectId: string }>()
  const navigate = useNavigate()
  const projects = useProjectStore((s) => s.projects)
  const fetchProjects = useProjectStore((s) => s.fetchProjects)
  const [expandedId, setExpandedId] = useState<string | null>(null)

  // Load projects on mount
  useEffect(() => {
    fetchProjects()
  }, [fetchProjects])

  // Auto-expand the active project
  useEffect(() => {
    if (activeProjectId) {
      setExpandedId(activeProjectId)
    }
  }, [activeProjectId])

  const toggleExpand = (id: string) => {
    setExpandedId((prev) => (prev === id ? null : id))
  }

  if (collapsed) {
    return (
      <aside className="flex h-full w-12 flex-col items-center border-r border-border bg-sidebar text-sidebar-foreground">
        <div className="flex h-14 items-center justify-center">
          <button
            onClick={onToggle}
            className="rounded p-1.5 text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground"
            title="Expand sidebar"
          >
            <PanelLeftOpen className="h-5 w-5" />
          </button>
        </div>
        <Separator />
        <nav className="flex-1 space-y-2 py-3">
          <NavLink
            to="/projects"
            title="Projects"
            className={({ isActive }) =>
              `flex items-center justify-center rounded-md p-2 transition-colors ${
                isActive
                  ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              }`
            }
          >
            <FolderOpen className="h-4 w-4" />
          </NavLink>
        </nav>
        <div className="pb-3">
          <NavLink
            to="/help"
            title="Help"
            className={({ isActive }) =>
              `flex items-center justify-center rounded-md p-2 transition-colors ${
                isActive
                  ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                  : 'text-sidebar-foreground/70 hover:bg-sidebar-accent/50 hover:text-sidebar-foreground'
              }`
            }
          >
            <HelpCircle className="h-4 w-4" />
          </NavLink>
        </div>
      </aside>
    )
  }

  return (
    <aside className="flex h-full w-64 flex-col border-r border-border bg-sidebar text-sidebar-foreground">
      <div className="flex h-14 items-center gap-2 px-4">
        <Shield className="h-6 w-6 text-primary" />
        <span className="text-lg font-semibold tracking-tight">Wairz</span>
        <button
          onClick={onToggle}
          className="ml-auto rounded p-0.5 text-muted-foreground hover:bg-sidebar-accent hover:text-sidebar-foreground"
          title="Collapse sidebar"
        >
          <PanelLeftClose className="h-4 w-4" />
        </button>
      </div>
      <Separator />

      {/* Projects header */}
      <div className="px-3 pb-1 pt-3">
        <NavLink
          to="/projects"
          end
          className={({ isActive }) =>
            `flex items-center gap-2 rounded-md px-2 py-1.5 text-xs font-semibold uppercase tracking-wide transition-colors ${
              isActive
                ? 'text-sidebar-accent-foreground'
                : 'text-muted-foreground hover:text-sidebar-foreground'
            }`
          }
        >
          <FolderOpen className="h-3.5 w-3.5" />
          Projects
        </NavLink>
      </div>

      {/* Project tree */}
      <nav className="flex-1 overflow-y-auto px-2 pb-3">
        {projects.length === 0 && (
          <p className="px-3 py-2 text-xs text-muted-foreground">No projects yet</p>
        )}
        {projects.map((project) => {
          const isExpanded = expandedId === project.id
          const isActive = activeProjectId === project.id

          return (
            <div key={project.id}>
              {/* Project row */}
              <button
                onClick={() => toggleExpand(project.id)}
                className={`flex w-full items-center gap-1.5 rounded-md px-2 py-1.5 text-sm transition-colors ${
                  isActive
                    ? 'bg-sidebar-accent/50 text-sidebar-accent-foreground'
                    : 'text-sidebar-foreground/80 hover:bg-sidebar-accent/30 hover:text-sidebar-foreground'
                }`}
              >
                <ChevronRight
                  className={`h-3.5 w-3.5 shrink-0 text-muted-foreground transition-transform ${
                    isExpanded ? 'rotate-90' : ''
                  }`}
                />
                <span className="min-w-0 truncate">{project.name}</span>
              </button>

              {/* Sub-pages */}
              {isExpanded && (
                <div className="ml-3 border-l border-border/50 pl-2">
                  {projectSubPages.map((page) => (
                    <NavLink
                      key={page.suffix}
                      to={`/projects/${project.id}${page.suffix}`}
                      end={page.suffix === ''}
                      onClick={(e) => {
                        e.stopPropagation()
                        navigate(`/projects/${project.id}${page.suffix}`)
                      }}
                      className={({ isActive: linkActive }) =>
                        `flex items-center gap-2 rounded-md px-2 py-1 text-xs font-medium transition-colors ${
                          linkActive
                            ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                            : 'text-sidebar-foreground/60 hover:bg-sidebar-accent/40 hover:text-sidebar-foreground'
                        }`
                      }
                    >
                      <page.icon className="h-3.5 w-3.5" />
                      {page.label}
                    </NavLink>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </nav>

      <div className="px-3 pb-1">
        <NavLink
          to="/help"
          className={({ isActive }) =>
            `flex items-center gap-2 rounded-md px-2 py-1.5 text-xs font-medium transition-colors ${
              isActive
                ? 'bg-sidebar-accent text-sidebar-accent-foreground'
                : 'text-sidebar-foreground/60 hover:bg-sidebar-accent/40 hover:text-sidebar-foreground'
            }`
          }
        >
          <HelpCircle className="h-3.5 w-3.5" />
          Help
        </NavLink>
      </div>
      <div className="px-4 py-3 text-xs text-muted-foreground">
        Firmware Security Analysis
      </div>
    </aside>
  )
}
