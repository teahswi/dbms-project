/** @type {import('tailwindcss').Config} */
export default {
  darkMode: 'class',
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        background: 'hsl(var(--background))',
        foreground: 'hsl(var(--foreground))',
        card: 'hsl(var(--card))',
        'card-foreground': 'hsl(var(--card-foreground))',
        border: 'hsl(var(--border))',
        primary: {
          DEFAULT: '#06b6d4', // Electric Cyan
          foreground: '#0f172a'
        },
        secondary: {
          DEFAULT: '#6366f1', // Electric Indigo
          foreground: '#ffffff'
        },
        muted: {
          DEFAULT: '#1e293b',
          foreground: '#94a3b8'
        },
        accent: {
          DEFAULT: '#0ea5e9',
          foreground: '#ffffff'
        },
        destructive: {
          DEFAULT: '#ef4444',
          foreground: '#ffffff'
        },
        // Strict Security Semantic Palette
        severity: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#0ea5e9',
          info: '#64748b'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
