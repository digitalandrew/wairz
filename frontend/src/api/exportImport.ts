import apiClient from './client'
import type { ProjectDetail } from '@/types'

export async function exportProject(projectId: string): Promise<Blob> {
  const { data } = await apiClient.post<Blob>(
    `/projects/${projectId}/export`,
    null,
    { responseType: 'blob', timeout: 600000 },
  )
  return data
}

export async function importProject(
  file: File,
  onProgress?: (pct: number) => void,
): Promise<ProjectDetail> {
  const form = new FormData()
  form.append('file', file)
  const { data } = await apiClient.post<ProjectDetail>('/projects/import', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    timeout: 600000,
    onUploadProgress: (e) => {
      if (onProgress && e.total) {
        onProgress(Math.round((e.loaded / e.total) * 100))
      }
    },
  })
  return data
}
