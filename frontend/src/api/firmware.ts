import apiClient from './client'
import type { FirmwareDetail, FirmwareMetadata, FirmwareSummary } from '@/types'

export async function uploadFirmware(
  projectId: string,
  file: File,
  versionLabel?: string,
  onProgress?: (percent: number) => void,
): Promise<FirmwareSummary> {
  const form = new FormData()
  form.append('file', file)
  if (versionLabel) {
    form.append('version_label', versionLabel)
  }

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

export async function listFirmware(
  projectId: string,
): Promise<FirmwareDetail[]> {
  const { data } = await apiClient.get<FirmwareDetail[]>(
    `/projects/${projectId}/firmware`,
  )
  return data
}

export async function getSingleFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.get<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}`,
  )
  return data
}

export async function deleteFirmware(
  projectId: string,
  firmwareId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/firmware/${firmwareId}`)
}

export async function unpackFirmware(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareDetail> {
  const { data } = await apiClient.post<FirmwareDetail>(
    `/projects/${projectId}/firmware/${firmwareId}/unpack`,
    null,
    { timeout: 600_000 },
  )
  return data
}

export async function getFirmwareMetadata(
  projectId: string,
  firmwareId: string,
): Promise<FirmwareMetadata> {
  const { data } = await apiClient.get<FirmwareMetadata>(
    `/projects/${projectId}/firmware/${firmwareId}/metadata`,
  )
  return data
}
