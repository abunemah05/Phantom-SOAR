import React from "react";
import Link from "next/link";

/** A status badge that links to a page only when the viewer's role may open it; otherwise a plain element. */
export default function BadgeWrap({
  href, className, title, children,
}: { href: string | null; className: string; title?: string; children: React.ReactNode }) {
  if (href) {
    return (
      <Link href={href} className={`${className} hover:brightness-125`} title={title}>
        {children}
      </Link>
    );
  }
  return <div className={className} title={title}>{children}</div>;
}
