import apiClient from './client'
import type { SecurityReview, ReviewCategory } from '@/types'

export async function createReview(
  projectId: string,
  categories: ReviewCategory[],
): Promise<SecurityReview> {
  const { data } = await apiClient.post<SecurityReview>(
    `/projects/${projectId}/reviews`,
    { categories },
  )
  return data
}

export async function listReviews(
  projectId: string,
): Promise<SecurityReview[]> {
  const { data } = await apiClient.get<SecurityReview[]>(
    `/projects/${projectId}/reviews`,
  )
  return data
}

export async function getReview(
  projectId: string,
  reviewId: string,
): Promise<SecurityReview> {
  const { data } = await apiClient.get<SecurityReview>(
    `/projects/${projectId}/reviews/${reviewId}`,
  )
  return data
}

export async function cancelReview(
  projectId: string,
  reviewId: string,
): Promise<void> {
  await apiClient.post(`/projects/${projectId}/reviews/${reviewId}/cancel`)
}

export function buildReviewSSEUrl(
  projectId: string,
  reviewId: string,
): string {
  return `/api/v1/projects/${projectId}/reviews/${reviewId}/stream`
}
