import apiClient from './client'
import type {
  EmulationSession,
  EmulationStartRequest,
  EmulationExecResponse,
  EmulationPreset,
  EmulationPresetCreate,
  EmulationPresetUpdate,
} from '@/types'

export async function startEmulation(
  projectId: string,
  request: EmulationStartRequest,
): Promise<EmulationSession> {
  const { data } = await apiClient.post<EmulationSession>(
    `/projects/${projectId}/emulation/start`,
    request,
  )
  return data
}

export async function stopEmulation(
  projectId: string,
  sessionId: string,
): Promise<EmulationSession> {
  const { data } = await apiClient.post<EmulationSession>(
    `/projects/${projectId}/emulation/${sessionId}/stop`,
  )
  return data
}

export async function execInEmulation(
  projectId: string,
  sessionId: string,
  command: string,
  timeout = 30,
): Promise<EmulationExecResponse> {
  const { data } = await apiClient.post<EmulationExecResponse>(
    `/projects/${projectId}/emulation/${sessionId}/exec`,
    { command, timeout },
  )
  return data
}

export async function listSessions(
  projectId: string,
): Promise<EmulationSession[]> {
  const { data } = await apiClient.get<EmulationSession[]>(
    `/projects/${projectId}/emulation/sessions`,
  )
  return data
}

export async function getSessionStatus(
  projectId: string,
  sessionId: string,
): Promise<EmulationSession> {
  const { data } = await apiClient.get<EmulationSession>(
    `/projects/${projectId}/emulation/${sessionId}/status`,
  )
  return data
}

export async function getSessionLogs(
  projectId: string,
  sessionId: string,
): Promise<string> {
  const { data } = await apiClient.get<{ logs: string }>(
    `/projects/${projectId}/emulation/${sessionId}/logs`,
  )
  return data.logs
}

export function buildEmulationTerminalURL(
  projectId: string,
  sessionId: string,
): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return `${proto}//${host}/api/v1/projects/${projectId}/emulation/${sessionId}/terminal`
}

// ── Emulation Presets ──

export async function listPresets(
  projectId: string,
): Promise<EmulationPreset[]> {
  const { data } = await apiClient.get<EmulationPreset[]>(
    `/projects/${projectId}/emulation/presets`,
  )
  return data
}

export async function createPreset(
  projectId: string,
  request: EmulationPresetCreate,
): Promise<EmulationPreset> {
  const { data } = await apiClient.post<EmulationPreset>(
    `/projects/${projectId}/emulation/presets`,
    request,
  )
  return data
}

export async function updatePreset(
  projectId: string,
  presetId: string,
  request: EmulationPresetUpdate,
): Promise<EmulationPreset> {
  const { data } = await apiClient.patch<EmulationPreset>(
    `/projects/${projectId}/emulation/presets/${presetId}`,
    request,
  )
  return data
}

export async function deletePreset(
  projectId: string,
  presetId: string,
): Promise<void> {
  await apiClient.delete(`/projects/${projectId}/emulation/presets/${presetId}`)
}
