import apiClient from './client'
import type { BinaryDiff, FirmwareDiff } from '@/types'

export async function diffFirmware(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
): Promise<FirmwareDiff> {
  const { data } = await apiClient.post<FirmwareDiff>(
    `/projects/${projectId}/compare/firmware`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId },
    { timeout: 300_000 },
  )
  return data
}

export async function diffBinary(
  projectId: string,
  firmwareAId: string,
  firmwareBId: string,
  binaryPath: string,
): Promise<BinaryDiff> {
  const { data } = await apiClient.post<BinaryDiff>(
    `/projects/${projectId}/compare/binary`,
    { firmware_a_id: firmwareAId, firmware_b_id: firmwareBId, binary_path: binaryPath },
    { timeout: 300_000 },
  )
  return data
}
