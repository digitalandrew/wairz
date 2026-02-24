import apiClient from './client'
import type { ProjectDetail } from '@/types'

export async function exportProject(projectId: string): Promise<Blob> {
  try {
    const { data } = await apiClient.post<Blob>(
      `/projects/${projectId}/export`,
      null,
      { responseType: 'blob', timeout: 600000 },
    )
    return data
  } catch (err) {
    // With responseType: 'blob', axios returns error bodies as Blob objects.
    // Parse the blob to extract the JSON error detail.
    let detail: string | undefined
    if (err && typeof err === 'object' && 'response' in err) {
      const resp = (err as { response?: { data?: Blob } }).response
      if (resp?.data instanceof Blob) {
        try {
          const text = await resp.data.text()
          const json = JSON.parse(text)
          detail = json.detail
        } catch {
          // blob wasn't valid JSON
        }
      }
    }
    throw detail ? new Error(detail) : err
  }
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
