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
        cyber: {
          dark: '#07090e',
          card: '#0e1320',
          cardHover: '#161e32',
          border: 'rgba(255, 255, 255, 0.08)',
          cyan: '#00f2fe',
          purple: '#7928ca',
          emerald: '#10b981',
          amber: '#f59e0b',
          crimson: '#ef4444'
        }
      },
      fontFamily: {
        sans: ['Outfit', 'Inter', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      },
      boxShadow: {
        'glow-cyan': '0 0 25px rgba(0, 242, 254, 0.25)',
        'glow-crimson': '0 0 25px rgba(239, 68, 68, 0.3)',
        'glow-emerald': '0 0 25px rgba(16, 185, 129, 0.25)',
      }
    },
  },
  plugins: [],
}
