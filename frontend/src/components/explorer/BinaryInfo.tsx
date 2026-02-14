import { useEffect, useState } from 'react'
import { Cpu, Shield, ShieldAlert, ShieldCheck, Loader2 } from 'lucide-react'
import { useParams } from 'react-router-dom'
import { getBinaryInfo } from '@/api/analysis'
import type { FileInfo, BinaryProtections } from '@/types'

interface BinaryInfoProps {
  fileInfo: FileInfo
}

function ProtectionBadge({ label, enabled }: { label: string; enabled: boolean }) {
  return (
    <span
      className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${
        enabled
          ? 'bg-green-500/15 text-green-400'
          : 'bg-red-500/15 text-red-400'
      }`}
    >
      {label}: {enabled ? 'Yes' : 'No'}
    </span>
  )
}

function RelroBadge({ value }: { value: string }) {
  const color =
    value === 'full'
      ? 'bg-green-500/15 text-green-400'
      : value === 'partial'
        ? 'bg-yellow-500/15 text-yellow-400'
        : 'bg-red-500/15 text-red-400'
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${color}`}>
      RELRO: {value}
    </span>
  )
}

function ProtectionsPanel({ protections }: { protections: BinaryProtections }) {
  if (protections.error) {
    return (
      <div className="text-xs text-muted-foreground">{protections.error}</div>
    )
  }

  const enabledCount =
    [protections.nx, protections.canary, protections.pie, protections.fortify].filter(Boolean).length +
    (protections.relro === 'full' ? 1 : protections.relro === 'partial' ? 0.5 : 0)

  const ShieldIcon = enabledCount >= 3.5 ? ShieldCheck : enabledCount >= 2 ? Shield : ShieldAlert
  const iconColor = enabledCount >= 3.5 ? 'text-green-400' : enabledCount >= 2 ? 'text-yellow-400' : 'text-red-400'

  return (
    <div>
      <div className="mb-2 flex items-center gap-2 text-sm font-medium">
        <ShieldIcon className={`h-4 w-4 ${iconColor}`} />
        Security Protections ({enabledCount}/5)
      </div>
      <div className="flex flex-wrap gap-1.5">
        <ProtectionBadge label="NX" enabled={protections.nx} />
        <RelroBadge value={protections.relro} />
        <ProtectionBadge label="Canary" enabled={protections.canary} />
        <ProtectionBadge label="PIE" enabled={protections.pie} />
        <ProtectionBadge label="Fortify" enabled={protections.fortify} />
        <span
          className={`inline-flex items-center rounded px-1.5 py-0.5 text-xs font-medium ${
            protections.stripped ? 'bg-yellow-500/15 text-yellow-400' : 'bg-muted text-muted-foreground'
          }`}
        >
          {protections.stripped ? 'Stripped' : 'Not stripped'}
        </span>
      </div>
    </div>
  )
}

export default function BinaryInfo({ fileInfo }: BinaryInfoProps) {
  const elf = fileInfo.elf_info as Record<string, string> | null
  const { projectId } = useParams<{ projectId: string }>()
  const [protections, setProtections] = useState<BinaryProtections | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    if (!projectId || !fileInfo.path || !elf) return
    setLoading(true)
    setProtections(null)
    getBinaryInfo(projectId, fileInfo.path)
      .then((resp) => setProtections(resp.protections))
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [projectId, fileInfo.path, elf])

  if (!elf) return null

  const fields = [
    { label: 'Type', value: elf.type },
    { label: 'Architecture', value: elf.machine },
    { label: 'Bits', value: elf.bits },
    { label: 'Endianness', value: elf.endianness },
    { label: 'Entry Point', value: elf.entry_point },
    { label: 'OS/ABI', value: elf.os_abi },
  ].filter((f) => f.value)

  return (
    <div className="space-y-3">
      {/* ELF header info */}
      <div className="rounded-md border border-border bg-muted/30 p-3">
        <div className="mb-2 flex items-center gap-2 text-sm font-medium">
          <Cpu className="h-4 w-4 text-muted-foreground" />
          ELF Binary Info
        </div>
        <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
          {fields.map((f) => (
            <div key={f.label} className="contents">
              <dt className="text-muted-foreground">{f.label}</dt>
              <dd className="font-mono">{f.value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Protections */}
      <div className="rounded-md border border-border bg-muted/30 p-3">
        {loading ? (
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <Loader2 className="h-3 w-3 animate-spin" />
            Loading protections…
          </div>
        ) : protections ? (
          <ProtectionsPanel protections={protections} />
        ) : (
          <div className="text-xs text-muted-foreground">
            Protections unavailable
          </div>
        )}
      </div>
    </div>
  )
}
