import { useId } from "react";

/**
 * Phantom SOAR brand mark: a ghost silhouette with a keyhole cut out of it
 * ("unseen threats, controlled access"). Purely decorative, so it is hidden
 * from assistive technology; the visible "PHANTOM SOAR" text names the product.
 */
export default function BrandMark({ className = "h-6 w-6" }: { className?: string }) {
  const gradientId = useId();
  return (
    <svg
      viewBox="0 0 64 64"
      className={className}
      aria-hidden="true"
      focusable="false"
      xmlns="http://www.w3.org/2000/svg"
    >
      <defs>
        <linearGradient id={gradientId} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0" stopColor="#FFFFFF" />
          <stop offset="1" stopColor="#8FB2FF" />
        </linearGradient>
      </defs>
      <path
        fillRule="evenodd"
        fill={`url(#${gradientId})`}
        d="M10 32C10 16.5 19.4 4 32 4C44.6 4 54 16.5 54 32V54A7.33 7.33 0 0 1 39.33 54A7.33 7.33 0 0 1 24.67 54A7.33 7.33 0 0 1 10 54ZM32 20A6 6 0 0 1 36.2 30.28L38 44H26L27.8 30.28A6 6 0 0 1 32 20Z"
      />
    </svg>
  );
}
