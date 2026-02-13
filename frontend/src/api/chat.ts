import apiClient from './client'
import type { Conversation, ConversationDetail } from '@/types'

export async function createConversation(
  projectId: string,
  title?: string,
): Promise<Conversation> {
  const { data } = await apiClient.post<Conversation>(
    `/projects/${projectId}/conversations`,
    { title: title ?? null },
  )
  return data
}

export async function listConversations(
  projectId: string,
): Promise<Conversation[]> {
  const { data } = await apiClient.get<Conversation[]>(
    `/projects/${projectId}/conversations`,
  )
  return data
}

export async function getConversation(
  projectId: string,
  conversationId: string,
): Promise<ConversationDetail> {
  const { data } = await apiClient.get<ConversationDetail>(
    `/projects/${projectId}/conversations/${conversationId}`,
  )
  return data
}

export function buildWebSocketURL(
  projectId: string,
  conversationId: string,
): string {
  const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
  const host = window.location.host
  return `${proto}//${host}/api/v1/projects/${projectId}/conversations/${conversationId}/ws`
}
