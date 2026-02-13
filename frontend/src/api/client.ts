import axios from 'axios'

const apiClient = axios.create({
  baseURL: '/api/v1',
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    const message =
      error.response?.data?.detail ?? error.message ?? 'An error occurred'
    console.error('[API Error]', message)
    return Promise.reject(error)
  },
)

export default apiClient
