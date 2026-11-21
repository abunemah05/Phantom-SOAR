/** @type {import('tailwindcss').Config} */
//
// Phantom SOAR "black console" theme.
//
// Every page and component styles itself with Tailwind's `slate` (neutrals) and
// `blue` (accent) scales. Re-defining those two scales here re-colors the whole
// app in one place without touching any component logic. Neutral steps are true
// black / graphite instead of blue-tinted slate; blue is the brighter
// "Phantom Blue" (#6E9BFF at 500).
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['"Inter Variable"', 'Inter', 'ui-sans-serif', 'system-ui', '-apple-system', '"Segoe UI"', 'Roboto', 'Arial', 'sans-serif'],
        mono: ['"JetBrains Mono Variable"', '"JetBrains Mono"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Consolas', 'monospace'],
      },
      colors: {
        background: '#000000',
        card: '#0a0a0a',
        'card-border': '#262626',
        slate: {
          50: '#fafafa',
          100: '#f5f5f5',
          200: '#e5e5e5',
          300: '#d4d4d4',
          400: '#a3a3a3',
          500: '#8a8a8a',
          600: '#737373',
          700: '#333333',
          800: '#262626',
          900: '#0a0a0a',
          950: '#000000',
        },
        blue: {
          50: '#eef3ff',
          100: '#dce7ff',
          200: '#bcd0ff',
          300: '#a3bfff',
          400: '#8aaeff',
          500: '#6e9bff',
          600: '#3f6fe0',
          700: '#2f56b8',
          800: '#233f8a',
          900: '#1a2f66',
          950: '#0e1a3a',
        },
      },
    },
  },
  plugins: [],
}
