/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        // Neutral ink / slate palette — calm, professional, no neon
        ink: {
          950: '#0a0e14',
          900: '#0d1219',
          850: '#111821',
          800: '#161e29',
          750: '#1c2733',
          700: '#23303e',
          600: '#2b3a4d',
          500: '#334558',
          400: '#4a5d72',
          300: '#6b7d93',
          200: '#9aa7b8',
          100: '#c4ccd6',
          50: '#e6e9ee',
        },
        // Single restrained accent — deep cobalt, used sparingly
        accent: {
          DEFAULT: '#3b6fd4',
          hover: '#4a7de0',
          soft: 'rgba(59, 111, 212, 0.14)',
          muted: 'rgba(59, 111, 212, 0.08)',
        },
        // Risk bands — desaturated, readable, no glow
        risk: {
          critical: '#c0392b',
          high: '#d97706',
          medium: '#b8860b',
          low: '#4a7c59',
        },
      },
      fontFamily: {
        // Clean editorial pairing: Inter for UI, a restrained serif for display
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        display: ['"Fraunces"', 'Georgia', 'serifer'],
        mono: ['"JetBrains Mono"', '"IBM Plex Mono"', 'monospace'],
      },
      boxShadow: {
        // Soft, diffused elevation — no neon halos
        card: '0 1px 2px rgba(0,0,0,.4), 0 8px 24px rgba(0,0,0,.25)',
        elevated: '0 2px 4px rgba(0,0,0,.45), 0 16px 40px rgba(0,0,0,.35)',
        focus: '0 0 0 3px rgba(59, 111, 212, 0.25)',
      },
      borderRadius: {
        card: '10px',
        button: '8px',
        input: '8px',
      },
      maxWidth: {
        content: '1280px',
      },
    },
  },
  plugins: [],
}