const UNITS = ['B', 'KB', 'MB', 'GB', 'TB'] as const

export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const i = Math.min(Math.floor(Math.log(bytes) / Math.log(1024)), UNITS.length - 1)
  const value = bytes / 1024 ** i
  return `${value < 10 && i > 0 ? value.toFixed(1) : Math.round(value)} ${UNITS[i]}`
}

const MINUTE = 60_000
const HOUR = 3_600_000
const DAY = 86_400_000

export function formatDate(iso: string): string {
  const date = new Date(iso)
  const diff = Date.now() - date.getTime()

  if (diff < MINUTE) return 'just now'
  if (diff < HOUR) return `${Math.floor(diff / MINUTE)}m ago`
  if (diff < DAY) return `${Math.floor(diff / HOUR)}h ago`
  if (diff < 7 * DAY) return `${Math.floor(diff / DAY)}d ago`

  return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric' })
}
