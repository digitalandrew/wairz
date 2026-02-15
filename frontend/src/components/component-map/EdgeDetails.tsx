import type { ComponentEdgeType } from '@/types'

interface EdgeDetailsProps {
  edgeType: ComponentEdgeType
  details: Record<string, unknown>
  source: string
  target: string
  position: { x: number; y: number }
  onClose: () => void
}

const edgeTypeLabels: Record<ComponentEdgeType, string> = {
  links_library: 'Links Library',
  imports_functions: 'Imports Functions',
  sources_script: 'Sources Script',
  executes: 'Executes',
  starts_service: 'Starts Service',
  configures: 'Configures',
}

export default function EdgeDetails({ edgeType, details, source, target, position, onClose }: EdgeDetailsProps) {
  const functions = (details.functions as string[] | undefined) ?? []

  return (
    <div
      className="fixed z-50 max-h-64 w-72 overflow-auto rounded-lg border border-border bg-popover p-3 shadow-lg"
      style={{ left: position.x, top: position.y }}
    >
      <div className="mb-2 flex items-center justify-between">
        <span className="text-xs font-semibold text-foreground">
          {edgeTypeLabels[edgeType] ?? edgeType}
        </span>
        <button
          onClick={onClose}
          className="text-xs text-muted-foreground hover:text-foreground"
        >
          x
        </button>
      </div>

      <div className="mb-2 space-y-1 text-[11px] text-muted-foreground">
        <div className="truncate"><span className="text-foreground/70">From:</span> {source}</div>
        <div className="truncate"><span className="text-foreground/70">To:</span> {target}</div>
      </div>

      {edgeType === 'imports_functions' && functions.length > 0 && (
        <div>
          <div className="mb-1 text-[11px] font-medium text-foreground/70">
            Functions ({functions.length}):
          </div>
          <div className="max-h-32 overflow-auto rounded bg-muted/50 p-1.5">
            {functions.map((fn) => (
              <div key={fn} className="truncate font-mono text-[10px] text-foreground/80">
                {fn}
              </div>
            ))}
          </div>
        </div>
      )}

      {edgeType === 'starts_service' && (
        <div className="space-y-1 text-[11px] text-muted-foreground">
          {'action' in details && <div><span className="text-foreground/70">Action:</span> {String(details.action)}</div>}
          {'variable' in details && <div><span className="text-foreground/70">Variable:</span> {String(details.variable)}</div>}
          {'exec_start' in details && <div className="truncate"><span className="text-foreground/70">ExecStart:</span> {String(details.exec_start)}</div>}
        </div>
      )}

      {edgeType === 'executes' && 'command' in details && (
        <div className="text-[11px] text-muted-foreground">
          <span className="text-foreground/70">Command:</span> {String(details.command)}
        </div>
      )}

      {edgeType === 'links_library' && 'library' in details && (
        <div className="text-[11px] text-muted-foreground">
          <span className="text-foreground/70">Library:</span> {String(details.library)}
        </div>
      )}
    </div>
  )
}
