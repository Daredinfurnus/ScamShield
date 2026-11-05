export const API = {
  health: '/health',
  investigations: '/api/investigations',
  analyzeText: '/api/analysis/text',
  analyzeUrl: '/api/analysis/url',
  analyzeImage: '/api/analysis/image',
  entities: (id) => `/api/investigations/${id}/entities`,
  reports: (id) => `/api/investigations/${id}/report`,
}