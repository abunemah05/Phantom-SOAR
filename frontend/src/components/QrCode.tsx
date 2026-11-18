"use client";

import React, { useMemo } from "react";
import qrcode from "qrcode-generator";

/**
 * QR code drawn as inline SVG from the module matrix (no HTML injection, no network, works under the CSP).
 * The value (an otpauth:// URI containing the TOTP secret) never leaves the browser.
 */
export default function QrCode({ value, label, size = 192 }: { value: string; label: string; size?: number }) {
  const geometry = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const count = qr.getModuleCount();
    const quiet = 4;
    let path = "";
    for (let row = 0; row < count; row++) {
      for (let col = 0; col < count; col++) {
        if (qr.isDark(row, col)) path += `M${col + quiet} ${row + quiet}h1v1h-1z`;
      }
    }
    return { path, extent: count + quiet * 2 };
  }, [value]);

  return (
    <svg
      role="img"
      aria-label={label}
      width={size}
      height={size}
      viewBox={`0 0 ${geometry.extent} ${geometry.extent}`}
      className="rounded-lg bg-white"
    >
      <rect width={geometry.extent} height={geometry.extent} fill="#ffffff" />
      <path d={geometry.path} fill="#000000" shapeRendering="crispEdges" />
    </svg>
  );
}
