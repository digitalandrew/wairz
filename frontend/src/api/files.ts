import apiClient from './client'
import type { DirectoryListing, FileContent, FileInfo } from '@/types'

export async function listDirectory(
  projectId: string,
  path: string = '',
): Promise<DirectoryListing> {
  const { data } = await apiClient.get<DirectoryListing>(
    `/projects/${projectId}/files`,
    { params: { path } },
  )
  return data
}

export async function readFile(
  projectId: string,
  path: string,
  offset?: number,
  length?: number,
): Promise<FileContent> {
  const { data } = await apiClient.get<FileContent>(
    `/projects/${projectId}/files/read`,
    { params: { path, offset, length } },
  )
  return data
}

export async function getFileInfo(
  projectId: string,
  path: string,
): Promise<FileInfo> {
  const { data } = await apiClient.get<FileInfo>(
    `/projects/${projectId}/files/info`,
    { params: { path } },
  )
  return data
}
