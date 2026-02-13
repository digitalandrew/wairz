import apiClient from './client'
import type { FirmwareDetail, FirmwareSummary } from '@/types'

export async function uploadFirmware(
  projectId: string,
  file: File,
  onProgress?: (percent: number) => void,
): Promise<FirmwareSummary> {
  const form = new FormData()
  form.append('file', file)

  const { data } = await apiClient.post<FirmwareSummary>(
    `/projects/${projectId}/firmware`,
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

export async function getFirmware(
  projectId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.get<FirmwareDetail>(
    `/projects/${projectId}/firmware`,
  )
  return data
}

export async function unpackFirmware(
  projectId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/unpack`,
    null,
    { timeout: 120_000 },
  )
  return data
}
