import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import {
  ChevronFirst,
  ChevronLast,
  ChevronLeft,
  ChevronRight,
  Loader2,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { readFile } from '@/api/files'

const CHUNK_SIZE = 4096
const BYTES_PER_ROW = 16

interface HexViewerProps {
  projectId: string
  filePath: string
  fileSize: number
}

function decodeBase64(b64: string): Uint8Array {
  const bin = atob(b64)
  const bytes = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i)
  }
  return bytes
}

function formatOffset(offset: number): string {
  return offset.toString(16).padStart(8, '0')
}

function isPrintable(byte: number): boolean {
  return byte >= 0x20 && byte < 0x7f
}

function interpretValues(bytes: Uint8Array): string[] {
  const parts: string[] = []
  if (bytes.length >= 1) {
    parts.push(`u8: ${bytes[0]}`)
  }
  if (bytes.length >= 2) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    parts.push(`u16LE: ${view.getUint16(0, true)}`)
    parts.push(`u16BE: ${view.getUint16(0, false)}`)
  }
  if (bytes.length >= 4) {
    const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength)
    parts.push(`u32LE: ${view.getUint32(0, true)}`)
    parts.push(`u32BE: ${view.getUint32(0, false)}`)
  }
  return parts
}

export default function HexViewer({ projectId, filePath, fileSize }: HexViewerProps) {
  const [data, setData] = useState<Uint8Array | null>(null)
  const [currentPage, setCurrentPage] = useState(0)
  const [loading, setLoading] = useState(false)
  const [selStart, setSelStart] = useState<number | null>(null)
  const [selEnd, setSelEnd] = useState<number | null>(null)
  const [selecting, setSelecting] = useState(false)
  const [goToValue, setGoToValue] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)

  const totalPages = Math.max(1, Math.ceil(fileSize / CHUNK_SIZE))

  // Load chunk when page or file changes
  useEffect(() => {
    let cancelled = false
    setLoading(true)
    setData(null)
    setSelStart(null)
    setSelEnd(null)

    const offset = currentPage * CHUNK_SIZE
    readFile(projectId, filePath, offset, CHUNK_SIZE, 'base64')
      .then((result) => {
        if (!cancelled) {
          setData(decodeBase64(result.content))
          setLoading(false)
        }
      })
      .catch(() => {
        if (!cancelled) {
          setData(null)
          setLoading(false)
        }
      })

    return () => {
      cancelled = true
    }
  }, [projectId, filePath, currentPage, fileSize])

  // End selection on global mouseup
  useEffect(() => {
    const handleMouseUp = () => setSelecting(false)
    window.addEventListener('mouseup', handleMouseUp)
    return () => window.removeEventListener('mouseup', handleMouseUp)
  }, [])

  const handleByteMouseDown = useCallback((index: number) => {
    setSelStart(index)
    setSelEnd(index)
    setSelecting(true)
  }, [])

  const handleByteMouseEnter = useCallback(
    (index: number) => {
      if (selecting) {
        setSelEnd(index)
      }
    },
    [selecting],
  )

  const selMin = selStart !== null && selEnd !== null ? Math.min(selStart, selEnd) : null
  const selMax = selStart !== null && selEnd !== null ? Math.max(selStart, selEnd) : null

  const isSelected = useCallback(
    (index: number) => selMin !== null && selMax !== null && index >= selMin && index <= selMax,
    [selMin, selMax],
  )

  const pageOffset = currentPage * CHUNK_SIZE

  // Selection info
  const selectionInfo = useMemo(() => {
    if (selMin === null || selMax === null || !data) return null
    const count = selMax - selMin + 1
    const absStart = pageOffset + selMin
    const absEnd = pageOffset + selMax
    const selectedBytes = data.slice(selMin, selMax + 1)
    const values = count <= 4 ? interpretValues(selectedBytes) : []
    return { count, absStart, absEnd, values }
  }, [selMin, selMax, data, pageOffset])

  const handleGoTo = useCallback(() => {
    const offset = parseInt(goToValue, 16)
    if (isNaN(offset) || offset < 0) return
    const page = Math.floor(offset / CHUNK_SIZE)
    if (page < totalPages) {
      setCurrentPage(page)
      setGoToValue('')
    }
  }, [goToValue, totalPages])

  if (!data && !loading) {
    return (
      <div className="flex items-center justify-center p-8 text-sm text-muted-foreground">
        Failed to load hex data.
      </div>
    )
  }

  const rows: number[][] = []
  if (data) {
    for (let i = 0; i < data.length; i += BYTES_PER_ROW) {
      const row: number[] = []
      for (let j = i; j < Math.min(i + BYTES_PER_ROW, data.length); j++) {
        row.push(j)
      }
      rows.push(row)
    }
  }

  return (
    <div className="flex h-full flex-col" ref={containerRef}>
      {/* Pagination toolbar */}
      <div className="flex items-center gap-2 border-b border-border px-3 py-1.5">
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={currentPage === 0 || loading}
          onClick={() => setCurrentPage(0)}
        >
          <ChevronFirst className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={currentPage === 0 || loading}
          onClick={() => setCurrentPage((p) => Math.max(0, p - 1))}
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        <span className="text-xs text-muted-foreground">
          Page {currentPage + 1} of {totalPages}{' '}
          <span className="font-mono">(0x{formatOffset(pageOffset)})</span>
        </span>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={currentPage >= totalPages - 1 || loading}
          onClick={() => setCurrentPage((p) => Math.min(totalPages - 1, p + 1))}
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
        <Button
          variant="ghost"
          size="icon"
          className="h-7 w-7"
          disabled={currentPage >= totalPages - 1 || loading}
          onClick={() => setCurrentPage(totalPages - 1)}
        >
          <ChevronLast className="h-4 w-4" />
        </Button>

        <div className="ml-auto flex items-center gap-1.5">
          <span className="text-xs text-muted-foreground">Go to:</span>
          <span className="text-xs text-muted-foreground font-mono">0x</span>
          <Input
            value={goToValue}
            onChange={(e) => setGoToValue(e.target.value.replace(/[^0-9a-fA-F]/g, ''))}
            onKeyDown={(e) => e.key === 'Enter' && handleGoTo()}
            className="h-7 w-24 font-mono text-xs"
            placeholder="offset"
          />
        </div>
        {loading && <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />}
      </div>

      {/* Hex grid */}
      <div className="flex-1 overflow-auto p-2 select-none">
        {loading && !data ? (
          <div className="flex items-center justify-center py-8">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : data ? (
          <table className="w-full border-collapse font-mono text-xs leading-5">
            <thead>
              <tr className="text-muted-foreground">
                <th className="pr-4 text-left font-normal">Offset</th>
                <th className="text-left font-normal" colSpan={2}>
                  Hex
                </th>
                <th className="pl-4 text-left font-normal">ASCII</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIdx) => {
                const rowOffset = pageOffset + rowIdx * BYTES_PER_ROW
                return (
                  <tr key={rowIdx} className="hover:bg-accent/30">
                    <td className="pr-4 text-muted-foreground whitespace-nowrap">
                      {formatOffset(rowOffset)}
                    </td>
                    {/* First 8 bytes */}
                    <td className="whitespace-nowrap">
                      {row.slice(0, 8).map((byteIdx) => (
                        <span
                          key={byteIdx}
                          className={`inline-block w-[1.75em] text-center cursor-pointer ${
                            isSelected(byteIdx)
                              ? 'bg-blue-600/60 text-white rounded-sm'
                              : 'hover:bg-accent'
                          }`}
                          onMouseDown={() => handleByteMouseDown(byteIdx)}
                          onMouseEnter={() => handleByteMouseEnter(byteIdx)}
                        >
                          {data[byteIdx].toString(16).padStart(2, '0')}
                        </span>
                      ))}
                      {/* Pad if row has fewer than 8 bytes */}
                      {row.length < 8 &&
                        Array.from({ length: 8 - row.length }).map((_, i) => (
                          <span key={`pad1-${i}`} className="inline-block w-[1.75em]">
                            {'  '}
                          </span>
                        ))}
                    </td>
                    {/* Last 8 bytes */}
                    <td className="whitespace-nowrap pl-2">
                      {row.slice(8).map((byteIdx) => (
                        <span
                          key={byteIdx}
                          className={`inline-block w-[1.75em] text-center cursor-pointer ${
                            isSelected(byteIdx)
                              ? 'bg-blue-600/60 text-white rounded-sm'
                              : 'hover:bg-accent'
                          }`}
                          onMouseDown={() => handleByteMouseDown(byteIdx)}
                          onMouseEnter={() => handleByteMouseEnter(byteIdx)}
                        >
                          {data[byteIdx].toString(16).padStart(2, '0')}
                        </span>
                      ))}
                      {/* Pad second half */}
                      {row.length > 8 && row.length < 16 &&
                        Array.from({ length: 16 - row.length }).map((_, i) => (
                          <span key={`pad2-${i}`} className="inline-block w-[1.75em]">
                            {'  '}
                          </span>
                        ))}
                      {row.length <= 8 &&
                        Array.from({ length: 8 }).map((_, i) => (
                          <span key={`pad2f-${i}`} className="inline-block w-[1.75em]">
                            {'  '}
                          </span>
                        ))}
                    </td>
                    {/* ASCII column */}
                    <td className="pl-4 whitespace-nowrap text-muted-foreground">
                      <span className="text-muted-foreground/50">|</span>
                      {row.map((byteIdx) => (
                        <span
                          key={byteIdx}
                          className={`inline-block w-[0.65em] text-center cursor-pointer ${
                            isSelected(byteIdx)
                              ? 'bg-blue-600/60 text-white rounded-sm'
                              : 'hover:bg-accent'
                          }`}
                          onMouseDown={() => handleByteMouseDown(byteIdx)}
                          onMouseEnter={() => handleByteMouseEnter(byteIdx)}
                        >
                          {isPrintable(data[byteIdx]) ? String.fromCharCode(data[byteIdx]) : '.'}
                        </span>
                      ))}
                      {/* Pad ASCII */}
                      {row.length < 16 &&
                        Array.from({ length: 16 - row.length }).map((_, i) => (
                          <span key={`apad-${i}`} className="inline-block w-[0.65em]">
                            {' '}
                          </span>
                        ))}
                      <span className="text-muted-foreground/50">|</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        ) : null}
      </div>

      {/* Selection info bar */}
      {selectionInfo && (
        <div className="flex items-center gap-4 border-t border-border px-3 py-1.5 text-xs text-muted-foreground">
          <span>
            {selectionInfo.count} byte{selectionInfo.count !== 1 ? 's' : ''} selected
          </span>
          <span className="font-mono">
            0x{formatOffset(selectionInfo.absStart)}
            {selectionInfo.count > 1 && ` - 0x${formatOffset(selectionInfo.absEnd)}`}
          </span>
          {selectionInfo.values.length > 0 && (
            <span className="font-mono">{selectionInfo.values.join(' | ')}</span>
          )}
        </div>
      )}
    </div>
  )
}
