import { Cpu } from 'lucide-react'
import type { FileInfo } from '@/types'

interface BinaryInfoProps {
  fileInfo: FileInfo
}

export default function BinaryInfo({ fileInfo }: BinaryInfoProps) {
  const elf = fileInfo.elf_info as Record<string, string> | null
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
      {fileInfo.sha256 && (
        <div className="mt-2 border-t border-border pt-2 text-xs">
          <span className="text-muted-foreground">SHA256: </span>
          <span className="font-mono break-all">{fileInfo.sha256}</span>
        </div>
      )}
    </div>
  )
}
