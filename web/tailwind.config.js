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
        background: '#090706',
        card: '#130f0c',
        'card-subtle': '#181310',
        border: '#261e18',
        'border-light': '#3b2f25',
        primary: {
          DEFAULT: '#f59e0b',
          light: '#fbbf24',
          dark: '#d97706',
          hover: '#f59e0b',
        },
        accent: {
          amber: '#f59e0b',
          copper: '#ea580c',
          peach: '#fbcfe8',
          gold: '#fbbf24',
        },
        danger: '#ef4444',
        warning: '#f59e0b',
        success: '#10b981',
      },
      boxShadow: {
        'amber-glow': '0 0 25px -5px rgba(245, 158, 11, 0.25)',
        'amber-glow-lg': '0 0 35px -5px rgba(245, 158, 11, 0.35)',
        'inner-light': 'inset 0 1px 0 0 rgba(255, 255, 255, 0.05)',
      }
    },
  },
  plugins: [],
}
