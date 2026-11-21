# Phantom SOAR brand and theme

The console uses a true-black theme with one blue accent. This page records the
choices so future changes stay consistent. The redesign is **visual only**: no
component logic, API call, permission or test hook was changed.

## Logo

A ghost silhouette with a keyhole cut out of it: unseen threats, controlled
access. It is the `BrandMark` component (`frontend/src/components/BrandMark.tsx`)
and the browser-tab icon (`frontend/src/app/icon.svg`). The wordmark is
**PHANTOM** (bold) followed by **SOAR** (light).

## Colors

All colors come from `frontend/tailwind.config.js`. The app styles itself with
Tailwind's `slate` (neutrals) and `blue` (accent) scales, so re-defining those two
scales re-colors every page in one place.

| Role | Value |
| --- | --- |
| Page background | `#000000` (`slate-950`) |
| Cards and menu | `#0A0A0A` (`slate-900`) |
| Borders | `#262626` (`slate-800`) |
| Text | `#F5F5F5`, muted `#A3A3A3` / `#737373` |
| Accent ("Phantom Blue") | `#6E9BFF` (`blue-500`) |
| Severity | critical red, high orange, medium yellow, low light blue (same colors as before; any shade taken from the `blue` scale follows the new blue) |

Primary buttons (`bg-blue-600 text-white` buttons and links) are shown as solid
white with black text by one rule in `frontend/src/app/globals.css`.

## Fonts

Inter (interface) and JetBrains Mono (IDs, hosts, timestamps), both self-hosted
through `@fontsource-variable/*`, so nothing is fetched from a third-party site at
runtime and the Content-Security-Policy (`font-src 'self'`) is unchanged.
