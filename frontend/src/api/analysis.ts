import apiClient from './client'
import type {
  FunctionListResponse,
  DisassemblyResponse,
  DecompilationResponse,
  BinaryInfoResponse,
} from '@/types'

export async function listFunctions(
  projectId: string,
  binaryPath: string,
): Promise<FunctionListResponse> {
  const { data } = await apiClient.get<FunctionListResponse>(
    `/projects/${projectId}/analysis/functions`,
    { params: { path: binaryPath } },
  )
  return data
}

export async function disassembleFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
  maxInstructions: number = 100,
): Promise<DisassemblyResponse> {
  const { data } = await apiClient.get<DisassemblyResponse>(
    `/projects/${projectId}/analysis/disasm`,
    { params: { path: binaryPath, function: functionName, max_instructions: maxInstructions } },
  )
  return data
}

export async function decompileFunction(
  projectId: string,
  binaryPath: string,
  functionName: string,
): Promise<DecompilationResponse> {
  const { data } = await apiClient.get<DecompilationResponse>(
    `/projects/${projectId}/analysis/decompile`,
    { params: { path: binaryPath, function: functionName } },
  )
  return data
}

export async function getBinaryInfo(
  projectId: string,
  binaryPath: string,
): Promise<BinaryInfoResponse> {
  const { data } = await apiClient.get<BinaryInfoResponse>(
    `/projects/${projectId}/analysis/binary-info`,
    { params: { path: binaryPath } },
  )
  return data
}
