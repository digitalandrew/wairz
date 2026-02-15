import apiClient from './client'
import type { ComponentGraph } from '@/types'

export async function getComponentMap(
  projectId: string,
): Promise<ComponentGraph> {
  const { data } = await apiClient.get<ComponentGraph>(
    `/projects/${projectId}/component-map`,
  )
  return data
}
