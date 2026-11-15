import axios from 'axios'
import { useAuthStore } from '../store/authStore'

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
  withCredentials: true, // send/receive HttpOnly access_token cookie
})

// Attach the stored JWT as a Bearer header for non-cookie clients and
// refresh the persisted state when a token is received from the server.
api.interceptors.request.use(
  (config) => {
    const { accessToken } = useAuthStore.getState()
    if (accessToken) {
      config.headers.Authorization = `Bearer ${accessToken}`
    }
    return config
  },
  (error) => Promise.reject(error),
)

api.interceptors.response.use(
  (response) => {
    // Mirror the JWT into local state whenever the server hands one back.
    const token = response.data?.access_token
    if (token) {
      const store = useAuthStore.getState()
      if (token !== store.accessToken) {
        store.setAuth(store.user, token)
      }
    }
    return response
  },
  (error) => {
    const status = error?.response?.status
    if (status === 401) {
      useAuthStore.getState().clearAuth()
    }
    return Promise.reject(error)
  },
)

export default api