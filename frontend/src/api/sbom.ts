import apiClient from './client'
import type {
  SbomComponent,
  SbomGenerateResponse,
  SbomSummary,
  SbomVulnerability,
  VulnerabilityScanResult,
} from '@/types'

export async function generateSbom(
  projectId: string,
  forceRescan = false,
): Promise<SbomGenerateResponse> {
  const { data } = await apiClient.post<SbomGenerateResponse>(
    `/projects/${projectId}/sbom/generate`,
    null,
    { params: { force_rescan: forceRescan } },
  )
  return data
}

export async function getSbomComponents(
  projectId: string,
  filters?: { type?: string; name?: string },
): Promise<SbomComponent[]> {
  const { data } = await apiClient.get<SbomComponent[]>(
    `/projects/${projectId}/sbom`,
    { params: filters },
  )
  return data
}

export async function exportSbom(
  projectId: string,
  format = 'cyclonedx-json',
): Promise<Blob> {
  const { data } = await apiClient.get(
    `/projects/${projectId}/sbom/export`,
    { params: { format }, responseType: 'blob' },
  )
  return data
}

export async function runVulnerabilityScan(
  projectId: string,
  forceRescan = false,
): Promise<VulnerabilityScanResult> {
  const { data } = await apiClient.post<VulnerabilityScanResult>(
    `/projects/${projectId}/sbom/vulnerabilities/scan`,
    null,
    { params: { force_rescan: forceRescan } },
  )
  return data
}

export async function getVulnerabilities(
  projectId: string,
  filters?: { severity?: string; component_id?: string; cve_id?: string },
): Promise<SbomVulnerability[]> {
  const { data } = await apiClient.get<SbomVulnerability[]>(
    `/projects/${projectId}/sbom/vulnerabilities`,
    { params: filters },
  )
  return data
}

export async function getVulnerabilitySummary(
  projectId: string,
): Promise<SbomSummary> {
  const { data } = await apiClient.get<SbomSummary>(
    `/projects/${projectId}/sbom/vulnerabilities/summary`,
  )
  return data
}
