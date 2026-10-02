/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        soc: {
          dark: '#0b0f19',
          card: '#111827',
          border: '#1f293d',
          sidebar: '#0d1322',
          accent: '#38bdf8',
          danger: '#ef4444',
          warning: '#f59e0b',
          success: '#10b981',
          muted: '#64748b'
        }
      }
    },
  },
  plugins: [],
}
