import { useCallback, useEffect, useRef, useState } from 'react'
import {
  FileText,
  Upload,
  Trash2,
  Download,
  Loader2,
  AlertCircle,
} from 'lucide-react'
import { Button } from '@/components/ui/button'
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Textarea } from '@/components/ui/textarea'
import { Progress } from '@/components/ui/progress'
import {
  listDocuments,
  uploadDocument,
  deleteDocument,
  getDocumentDownloadUrl,
} from '@/api/documents'
import { formatFileSize, formatDate } from '@/utils/format'
import type { ProjectDocument } from '@/types'

const MAX_DOCUMENTS = 20
const ALLOWED_EXTENSIONS = '.txt,.md,.pdf,.doc,.docx,.csv,.json,.xml,.html'

interface DocumentsCardProps {
  projectId: string
}

export default function DocumentsCard({ projectId }: DocumentsCardProps) {
  const [documents, setDocuments] = useState<ProjectDocument[]>([])
  const [loading, setLoading] = useState(true)
  const [uploading, setUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0)
  const [error, setError] = useState('')
  const [showUploadForm, setShowUploadForm] = useState(false)
  const [description, setDescription] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  const fetchDocuments = useCallback(async () => {
    try {
      const docs = await listDocuments(projectId)
      setDocuments(docs)
    } catch {
      // silently handle — documents are supplementary
    } finally {
      setLoading(false)
    }
  }, [projectId])

  useEffect(() => {
    fetchDocuments()
  }, [fetchDocuments])

  const handleUpload = async (file: File) => {
    setError('')
    setUploading(true)
    setUploadProgress(0)
    try {
      await uploadDocument(
        projectId,
        file,
        description || undefined,
        (pct) => setUploadProgress(pct),
      )
      setDescription('')
      setShowUploadForm(false)
      await fetchDocuments()
    } catch (e) {
      const msg =
        (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
        (e instanceof Error ? e.message : 'Upload failed')
      setError(msg)
    } finally {
      setUploading(false)
      if (fileInputRef.current) fileInputRef.current.value = ''
    }
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleUpload(file)
  }

  const handleDelete = async (docId: string, filename: string) => {
    if (!window.confirm(`Delete document "${filename}"?`)) return
    try {
      await deleteDocument(projectId, docId)
      setDocuments((prev) => prev.filter((d) => d.id !== docId))
    } catch {
      setError('Failed to delete document')
    }
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <FileText className="h-4 w-4" />
            Project Documents
            <span className="text-xs font-normal text-muted-foreground">
              {documents.length} / {MAX_DOCUMENTS}
            </span>
          </CardTitle>
          {documents.length < MAX_DOCUMENTS && (
            <Button
              variant="outline"
              size="sm"
              onClick={() => setShowUploadForm(!showUploadForm)}
              disabled={uploading}
            >
              <Upload className="mr-2 h-3.5 w-3.5" />
              Upload
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && (
          <div className="flex items-center gap-2 text-sm text-destructive">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {showUploadForm && (
          <div className="space-y-2 rounded-md border p-3">
            <Textarea
              placeholder="Description (optional) — e.g., scope document, prior pentest report..."
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              rows={2}
              className="text-sm"
            />
            <div className="flex items-center gap-2">
              <Input
                ref={fileInputRef}
                type="file"
                accept={ALLOWED_EXTENSIONS}
                onChange={handleFileSelect}
                disabled={uploading}
                className="text-sm"
              />
            </div>
            {uploading && (
              <div className="space-y-1">
                <Progress value={uploadProgress} className="h-2" />
                <p className="text-xs text-muted-foreground text-center">{uploadProgress}%</p>
              </div>
            )}
          </div>
        )}

        {loading ? (
          <div className="flex items-center justify-center py-4 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />
            <span className="text-sm">Loading documents...</span>
          </div>
        ) : documents.length === 0 ? (
          <p className="text-sm text-muted-foreground py-2">
            No documents uploaded. Upload scope documents, reports, or other reference materials for the AI assistant to use.
          </p>
        ) : (
          <div className="space-y-1.5">
            {documents.map((doc) => (
              <div
                key={doc.id}
                className="flex items-center justify-between gap-2 rounded-md border px-3 py-2 text-sm"
              >
                <div className="flex-1 min-w-0">
                  <div className="font-medium truncate">{doc.original_filename}</div>
                  {doc.description && (
                    <div className="text-xs text-muted-foreground truncate">
                      {doc.description}
                    </div>
                  )}
                  <div className="text-xs text-muted-foreground">
                    {formatFileSize(doc.file_size)} &middot; {formatDate(doc.created_at)}
                  </div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <Button variant="ghost" size="icon" className="h-7 w-7" asChild>
                    <a
                      href={getDocumentDownloadUrl(projectId, doc.id)}
                      download
                      title="Download"
                    >
                      <Download className="h-3.5 w-3.5" />
                    </a>
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7 text-destructive hover:text-destructive"
                    onClick={() => handleDelete(doc.id, doc.original_filename)}
                    title="Delete"
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  )
}
