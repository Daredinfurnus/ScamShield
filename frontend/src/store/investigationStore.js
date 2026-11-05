import { create } from 'zustand'

// Placeholder store. If zustand is not installed, this file is unused until added.
export const useInvestigationStore = create((set) => ({
  current: null,
  setCurrent: (c) => set({ current: c }),
}))