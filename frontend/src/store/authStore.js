import { create } from 'zustand'
import { persist } from 'zustand/middleware'

/**
 * Auth state store (Zustand, persisted to localStorage).
 *
 * Holds the authenticated user profile and the JWT access token.
 * The token is also mirrored into the HttpOnly cookie set by the auth
 * endpoints, but keeping it here lets the Axios interceptor attach it as
 * a Bearer header for non-cookie clients (mobile / SPA refresh).
 */
export const useAuthStore = create(
  persist(
    (set, get) => ({
      user: null,
      accessToken: null,
      status: 'idle', // idle | loading | authenticated | error
      authModalOpen: false, // Modal visibility state

      setAuth: (user, accessToken) =>
        set({ user, accessToken, status: 'authenticated' }),
      clearAuth: () =>
        set({ user: null, accessToken: null, status: 'idle' }),
      setError: (message) =>
        set({ status: 'error', error: message }),
      resetError: () => set({ error: null }),
      openAuthModal: () => set({ authModalOpen: true }),
      closeAuthModal: () => set({ authModalOpen: false }),
      toggleAuthModal: () => set((state) => ({ authModalOpen: !state.authModalOpen })),
    }),
    {
      name: 'scamshield-auth',
      partialize: (state) => ({
        user: state.user,
        accessToken: state.accessToken,
        status: state.status,
        // Don't persist modal state
      }),
    },
  ),
)

export default useAuthStore