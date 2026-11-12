/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        // Editorial Noir palette
        noir: {
          main: '#11110F',
          secondary: '#181814',
          card: '#201F1B',
          elevated: '#292820',
        },
        brand: {
          DEFAULT: '#C78332',
          secondary: '#77745D',
        },
        text: {
          primary: '#E9DFCC',
          secondary: '#A9A18F',
        },
        border: {
          DEFAULT: '#393831',
        },
        risk: {
          critical: '#B25C60',
          high: '#CD6C4A',
          medium: '#CA9E48',
          low: '#9CAF88',
        },
      },
      fontFamily: {
        display: ['"Bebas Neue"', 'sans-serif'],
        mono: ['"IBM Plex Mono"', 'monospace'],
        sans: ['"Inter"', 'sans-serif'],
      },
    },
  },
  plugins: [],
}