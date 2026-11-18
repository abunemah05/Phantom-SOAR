"use client";

import React, { useEffect, useId, useRef, useState } from "react";
import { createPortal } from "react-dom";
import { X } from "lucide-react";

// Accessible modal behaviour shared by every dialog and drawer in the console:
//  - focus moves into the dialog on open, is trapped while open, and returns to the opener on close
//  - Escape closes only the top-most dialog (stacked dialogs, e.g. a confirmation above a case drawer)
//  - the page behind does not scroll

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]):not([type="hidden"]), select:not([disabled]), [tabindex]:not([tabindex="-1"])';

const stack: symbol[] = [];
let scrollLocks = 0;

function focusableIn(container: HTMLElement): HTMLElement[] {
  return Array.from(container.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
    (el) => !el.hasAttribute("disabled") && el.getAttribute("aria-hidden") !== "true" && el.offsetParent !== null
  );
}

/** Attach focus trap, Escape handling, scroll lock and focus restoration to a container while `open`. */
export function useModalBehavior(
  containerRef: React.RefObject<HTMLElement>,
  open: boolean,
  onClose: () => void,
  options?: { closeOnEscape?: boolean; initialFocusRef?: React.RefObject<HTMLElement> }
): void {
  const onCloseRef = useRef(onClose);
  const closeOnEscape = options?.closeOnEscape ?? true;
  const initialFocusRef = options?.initialFocusRef;

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;
    const container = containerRef.current;
    if (!container) return;

    const token = Symbol("dialog");
    stack.push(token);
    const opener = document.activeElement instanceof HTMLElement ? document.activeElement : null;

    scrollLocks += 1;
    if (scrollLocks === 1) document.body.style.overflow = "hidden";

    // Move focus inside: the requested element, else the first control, else the container itself.
    const target = initialFocusRef?.current || focusableIn(container)[0] || container;
    target.focus();

    const onKeyDown = (event: KeyboardEvent) => {
      if (stack[stack.length - 1] !== token) return; // only the top-most dialog reacts
      if (event.key === "Escape" && closeOnEscape) {
        event.stopPropagation();
        onCloseRef.current();
        return;
      }
      if (event.key !== "Tab") return;
      const items = focusableIn(container);
      if (items.length === 0) {
        event.preventDefault();
        container.focus();
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      const active = document.activeElement;
      if (event.shiftKey && (active === first || !container.contains(active))) {
        event.preventDefault();
        last.focus();
      } else if (!event.shiftKey && (active === last || !container.contains(active))) {
        event.preventDefault();
        first.focus();
      }
    };
    document.addEventListener("keydown", onKeyDown, true);

    return () => {
      document.removeEventListener("keydown", onKeyDown, true);
      const index = stack.indexOf(token);
      if (index >= 0) stack.splice(index, 1);
      scrollLocks = Math.max(0, scrollLocks - 1);
      if (scrollLocks === 0) document.body.style.overflow = "";
      if (opener && document.contains(opener)) opener.focus();
    };
  }, [open, containerRef, closeOnEscape, initialFocusRef]);
}

/** Portal target that only exists in the browser. */
export function useIsClient(): boolean {
  const [client, setClient] = useState(false);
  useEffect(() => setClient(true), []);
  return client;
}

const SIZES: Record<string, string> = {
  sm: "max-w-md",
  md: "max-w-lg",
  lg: "max-w-2xl",
  xl: "max-w-4xl",
};

export interface DialogProps {
  open: boolean;
  onClose: () => void;
  title: string;
  description?: React.ReactNode;
  children?: React.ReactNode;
  footer?: React.ReactNode;
  size?: keyof typeof SIZES;
  /** "alertdialog" for confirmations that need an explicit answer. */
  role?: "dialog" | "alertdialog";
  /** Escape and backdrop clicks close the dialog unless this is false (e.g. a one-time secret). */
  dismissible?: boolean;
  hideCloseButton?: boolean;
  initialFocusRef?: React.RefObject<HTMLElement>;
  icon?: React.ReactNode;
}

export default function Dialog({
  open,
  onClose,
  title,
  description,
  children,
  footer,
  size = "md",
  role = "dialog",
  dismissible = true,
  hideCloseButton = false,
  initialFocusRef,
  icon,
}: DialogProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const titleId = useId();
  const descId = useId();
  const client = useIsClient();

  useModalBehavior(containerRef, open && client, onClose, { closeOnEscape: dismissible, initialFocusRef });

  if (!open || !client) return null;

  return createPortal(
    <div
      className="fixed inset-0 z-[70] flex items-center justify-center p-4 bg-slate-950/80 backdrop-blur-sm"
      onMouseDown={(e) => {
        if (dismissible && e.target === e.currentTarget) onClose();
      }}
    >
      <div
        ref={containerRef}
        role={role}
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={description ? descId : undefined}
        tabIndex={-1}
        className={`w-full ${SIZES[size]} max-h-[90vh] flex flex-col bg-slate-900 border border-slate-700 rounded-2xl shadow-2xl shadow-black/60 outline-none animate-fade-in`}
      >
        <div className="flex items-start justify-between gap-3 p-5 pb-3 border-b border-slate-800">
          <div className="flex items-start gap-3 min-w-0">
            {icon}
            <div className="min-w-0">
              <h2 id={titleId} className="text-base font-bold text-white">
                {title}
              </h2>
              {description && (
                <div id={descId} className="text-xs text-slate-400 mt-1 leading-relaxed">
                  {description}
                </div>
              )}
            </div>
          </div>
          {!hideCloseButton && dismissible && (
            <button
              type="button"
              onClick={onClose}
              aria-label="Close dialog"
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500"
            >
              <X className="h-4 w-4" />
            </button>
          )}
        </div>
        {children && <div className="p-5 overflow-y-auto text-sm text-slate-300 space-y-3">{children}</div>}
        {footer && <div className="p-4 border-t border-slate-800 flex flex-wrap items-center justify-end gap-2">{footer}</div>}
      </div>
    </div>,
    document.body
  );
}
