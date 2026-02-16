import apiClient from './client'
import type { KernelInfo, KernelListResponse } from '@/types'

export async function listKernels(
  architecture?: string,
): Promise<KernelListResponse> {
  const params: Record<string, string> = {}
  if (architecture) params.architecture = architecture
  const { data } = await apiClient.get<KernelListResponse>('/kernels', { params })
  return data
}

export async function uploadKernel(
  name: string,
  architecture: string,
  description: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<KernelInfo> {
  const form = new FormData()
  form.append('name', name)
  form.append('architecture', architecture)
  form.append('description', description)
  form.append('file', file)

  const { data } = await apiClient.post<KernelInfo>('/kernels', form, {
    headers: { 'Content-Type': 'multipart/form-data' },
    onUploadProgress: (e) => {
      if (e.total && onProgress) {
        onProgress(Math.round((e.loaded * 100) / e.total))
      }
    },
  })
  return data
}

export async function deleteKernel(kernelName: string): Promise<void> {
  await apiClient.delete(`/kernels/${encodeURIComponent(kernelName)}`)
}
