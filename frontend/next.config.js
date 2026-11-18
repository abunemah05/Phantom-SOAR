/** @type {import('next').NextConfig} */

const isDev = process.env.NODE_ENV !== "production";

// The browser talks to the API either through the Next rewrite below (same origin, "self") or, when
// NEXT_PUBLIC_API_URL is set at build time, directly; in that case its origin must be allowed by connect-src.
function apiOrigin() {
  const raw = process.env.NEXT_PUBLIC_API_URL;
  if (!raw) return "";
  try {
    return new URL(raw).origin;
  } catch {
    return "";
  }
}

// Content-Security-Policy. See frontend/SECURITY-NOTES.md for what is and is not covered.
//  - script-src needs 'unsafe-inline' because the App Router streams inline bootstrap scripts; a per-request nonce
//    (middleware) is the next step. 'unsafe-eval' is only added for `next dev` (React refresh).
//  - style-src needs 'unsafe-inline' for the style attributes React/Next emit.
//  - Everything else is locked down: no plugins, no framing, no foreign form targets, no base-tag hijacking,
//    and network access only to this origin and the configured API origin.
function contentSecurityPolicy() {
  const connect = ["'self'", apiOrigin()].filter(Boolean);
  if (isDev) connect.push("ws:", "http://localhost:*");
  const directives = {
    "default-src": ["'self'"],
    "script-src": ["'self'", "'unsafe-inline'", ...(isDev ? ["'unsafe-eval'"] : [])],
    "style-src": ["'self'", "'unsafe-inline'"],
    "img-src": ["'self'", "data:", "blob:"],
    "font-src": ["'self'", "data:"],
    "connect-src": connect,
    "object-src": ["'none'"],
    "base-uri": ["'self'"],
    "form-action": ["'self'"],
    "frame-ancestors": ["'none'"],
    "manifest-src": ["'self'"],
    "worker-src": ["'self'", "blob:"],
  };
  // upgrade-insecure-requests is deliberately not set: the default deployment is plain http://localhost and it
  // would rewrite the API calls to https. Add it when the console is served over TLS.
  return Object.entries(directives)
    .map(([name, values]) => `${name} ${values.join(" ")}`)
    .join("; ");
}

const securityHeaders = [
  { key: "Content-Security-Policy", value: contentSecurityPolicy() },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=(), payment=(), usb=(), interest-cohort=()" },
  { key: "Cross-Origin-Opener-Policy", value: "same-origin" },
  { key: "Cross-Origin-Resource-Policy", value: "same-origin" },
  // Only honoured by browsers over HTTPS; terminate TLS in front of the console (see SECURITY-NOTES.md).
  { key: "Strict-Transport-Security", value: "max-age=31536000" },
  { key: "X-DNS-Prefetch-Control", value: "off" },
];

const nextConfig = {
  reactStrictMode: true,
  output: "standalone",
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
  async rewrites() {
    return [
      {
        source: "/api/:path*",
        destination: process.env.NEXT_PUBLIC_API_URL
          ? `${process.env.NEXT_PUBLIC_API_URL}/api/:path*`
          : "http://localhost:8000/api/:path*",
      },
    ];
  },
};

module.exports = nextConfig;
