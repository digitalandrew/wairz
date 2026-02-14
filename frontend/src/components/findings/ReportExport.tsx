import { useState } from 'react'
import { Download, Loader2, ChevronDown, FileText, FileDown } from 'lucide-react'
import { Button } from '@/components/ui/button'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { exportFindings } from '@/api/findings'

type ExportFormat = 'markdown' | 'pdf'

const FORMAT_CONFIG: Record<ExportFormat, { label: string; ext: string; icon: typeof FileText }> = {
  markdown: { label: 'Markdown (.md)', ext: '.md', icon: FileText },
  pdf: { label: 'PDF (.pdf)', ext: '.pdf', icon: FileDown },
}

interface ReportExportProps {
  projectId: string
}

export default function ReportExport({ projectId }: ReportExportProps) {
  const [exporting, setExporting] = useState(false)

  const handleExport = async (format: ExportFormat) => {
    setExporting(true)
    try {
      const blob = await exportFindings(projectId, format)
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `security_report${FORMAT_CONFIG[format].ext}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Export failed:', err)
    } finally {
      setExporting(false)
    }
  }

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="sm" disabled={exporting}>
          {exporting ? (
            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
          ) : (
            <Download className="mr-2 h-4 w-4" />
          )}
          Export Report
          <ChevronDown className="ml-1 h-3 w-3" />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end">
        {(Object.entries(FORMAT_CONFIG) as [ExportFormat, typeof FORMAT_CONFIG[ExportFormat]][]).map(
          ([format, config]) => {
            const Icon = config.icon
            return (
              <DropdownMenuItem key={format} onClick={() => handleExport(format)}>
                <Icon className="mr-2 h-4 w-4" />
                {config.label}
              </DropdownMenuItem>
            )
          },
        )}
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
