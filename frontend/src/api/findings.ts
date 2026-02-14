import apiClient from './client'
import type { Finding, FindingCreate, FindingUpdate } from '@/types'

export async function listFindings(
  projectId: string,
  params?: { severity?: string; status?: string },
): Promise<Finding[]> {
  const { data } = await apiClient.get<Finding[]>(
    `/projects/${projectId}/findings`,
    { params },
  )
  return data
}

export async function getFinding(
  projectId: string,
  findingId: string,
): Promise<Finding> {
  const { data } = await apiClient.get<Finding>(
    `/projects/${projectId}/findings/${findingId}`,
  )
  return data
}

export async function createFinding(
  projectId: string,
  body: FindingCreate,
): Promise<Finding> {
  const { data } = await apiClient.post<Finding>(
    `/projects/${projectId}/findings`,
    body,
  )
  return data
}

export async function updateFinding(
  projectId: string,
  findingId: string,
  body: FindingUpdate,
): Promise<Finding> {
  const { data } = await apiClient.patch<Finding>(
    `/projects/${projectId}/findings/${findingId}`,
    body,
  )
  return data
}

export async function deleteFinding(
  projectId: string,
  findingId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/findings/${findingId}`)
}

export async function exportFindings(
  projectId: string,
  format: 'markdown' | 'pdf' = 'markdown',
): Promise<Blob> {
  const { data } = await apiClient.post(
    `/projects/${projectId}/findings/export`,
    null,
    { params: { format }, responseType: 'blob' },
  )
  return data
}
