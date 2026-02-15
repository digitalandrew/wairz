export function buildTerminalWebSocketURL(projectId: string): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return `${proto}//${host}/api/v1/projects/${projectId}/terminal/ws`
}
