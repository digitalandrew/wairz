import apiClient from './client'
import type { ProjectDocument, DocumentContent } from '@/types'

export async function listDocuments(projectId: string): Promise<ProjectDocument[]> {
  const { data } = await apiClient.get<ProjectDocument[]>(
    `/projects/${projectId}/documents`,
  )
  return data
}

export async function uploadDocument(
  projectId: string,
  file: File,
  description?: string,
  onProgress?: (percent: number) => void,
): Promise<ProjectDocument> {
  const form = new FormData()
  form.append('file', file)
  if (description) {
    form.append('description', description)
  }

  const { data } = await apiClient.post<ProjectDocument>(
    `/projects/${projectId}/documents`,
    form,
    {
      headers: { 'Content-Type': 'multipart/form-data' },
      onUploadProgress: (e) => {
        if (e.total && onProgress) {
          onProgress(Math.round((e.loaded * 100) / e.total))
        }
      },
    },
  )
  return data
}

export async function updateDocument(
  projectId: string,
  documentId: string,
  data: { description?: string | null },
): Promise<ProjectDocument> {
  const { data: doc } = await apiClient.patch<ProjectDocument>(
    `/projects/${projectId}/documents/${documentId}`,
    data,
  )
  return doc
}

export async function deleteDocument(
  projectId: string,
  documentId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/documents/${documentId}`)
}

export async function readDocumentContent(
  projectId: string,
  documentId: string,
): Promise<DocumentContent> {
  const { data } = await apiClient.get<DocumentContent>(
    `/projects/${projectId}/documents/${documentId}/content`,
  )
  return data
}

export async function createNote(
  projectId: string,
  title: string,
  content?: string,
): Promise<ProjectDocument> {
  const { data } = await apiClient.post<ProjectDocument>(
    `/projects/${projectId}/documents/notes`,
    { title, content: content ?? '' },
  )
  return data
}

export async function updateDocumentContent(
  projectId: string,
  documentId: string,
  content: string,
): Promise<ProjectDocument> {
  const { data } = await apiClient.put<ProjectDocument>(
    `/projects/${projectId}/documents/${documentId}/content`,
    { content },
  )
  return data
}

export function getDocumentDownloadUrl(projectId: string, documentId: string): string {
  return `/api/v1/projects/${projectId}/documents/${documentId}/download`
}
