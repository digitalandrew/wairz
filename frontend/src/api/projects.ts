import apiClient from './client'
import type { Project, ProjectDetail } from '@/types'

export async function listProjects(): Promise<Project[]> {
  const { data } = await apiClient.get<Project[]>('/projects')
  return data
}

export async function getProject(id: string): Promise<ProjectDetail> {
  const { data } = await apiClient.get<ProjectDetail>(`/projects/${id}`)
  return data
}

export async function createProject(params: {
  name: string
  description?: string
}): Promise<ProjectDetail> {
  const { data } = await apiClient.post<ProjectDetail>('/projects', params)
  return data
}

export async function deleteProject(id: string): Promise<void> {
  await apiClient.delete(`/projects/${id}`)
}
