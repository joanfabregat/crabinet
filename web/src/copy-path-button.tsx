import { type JSX } from "preact";
import { Check, Copy, X } from "lucide-preact";
import { useEffect, useRef, useState } from "preact/hooks";

import { useToast } from "./toast";

export function CopyPathButton({
  value,
  label,
  className = "icon-button",
  size = 19,
  text,
  role,
  copiedMessage = `Copied ${value}`,
  fallbackTitle = "Copy full path",
  fallbackLabel = "Select and copy this path",
}: {
  value: string;
  label: string;
  className?: string;
  size?: number;
  /** A visible label, for menus; icon-only buttons use a tooltip instead. */
  text?: string;
  role?: JSX.AriaRole;
  /** The confirmation shown once the value is on the clipboard. */
  copiedMessage?: string;
  /** Names the dialog offered when the clipboard is unavailable. */
  fallbackTitle?: string;
  fallbackLabel?: string;
}) {
  const [copied, setCopied] = useState(false);
  const [showFallback, setShowFallback] = useState(false);
  const fallbackInput = useRef<HTMLInputElement & HTMLTextAreaElement>(null);
  const copyButton = useRef<HTMLButtonElement>(null);
  const fallbackPanel = useRef<HTMLDivElement>(null);
  const showToast = useToast();
  // A multi-line value, such as a file's source, needs a text area to keep
  // its line breaks.
  const multiline = value.includes("\n");

  useEffect(() => {
    if (showFallback) {
      fallbackInput.current?.focus();
      fallbackInput.current?.select();
      return () => copyButton.current?.focus();
    }
  }, [showFallback]);

  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText)
        throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(value);
      setCopied(true);
      showToast(copiedMessage);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setShowFallback(true);
    }
  };

  return (
    <>
      <button
        ref={copyButton}
        class={text ? className : `${className} tooltip-action`}
        role={role}
        type="button"
        aria-label={label}
        data-tooltip={text ? undefined : copied ? "Copied" : label}
        onClick={() => void copy()}
      >
        {copied ? (
          <Check size={size} aria-hidden="true" />
        ) : (
          <Copy size={size} aria-hidden="true" />
        )}
        {text && <span>{copied ? "Copied" : text}</span>}
      </button>
      {showFallback && (
        <div class="modal-backdrop copy-fallback-backdrop">
          <div
            ref={fallbackPanel}
            class="modal-panel copy-fallback"
            role="dialog"
            aria-modal="true"
            aria-labelledby="copy-path-title"
            onKeyDown={(event) => {
              if (event.key === "Escape") {
                event.preventDefault();
                event.stopPropagation();
                setShowFallback(false);
              } else if (event.key === "Tab") {
                event.stopPropagation();
                const controls =
                  fallbackPanel.current?.querySelectorAll<HTMLElement>(
                    "button, input, textarea",
                  );
                const first = controls?.[0],
                  last = controls?.[controls.length - 1];
                if (event.shiftKey && document.activeElement === first) {
                  event.preventDefault();
                  last?.focus();
                } else if (!event.shiftKey && document.activeElement === last) {
                  event.preventDefault();
                  first?.focus();
                }
              }
            }}
          >
            <div class="modal-header">
              <h2 id="copy-path-title">{fallbackTitle}</h2>
              <button
                class="modal-close"
                type="button"
                aria-label={`Close ${fallbackTitle.toLowerCase()}`}
                onClick={() => setShowFallback(false)}
              >
                <X size={20} aria-hidden="true" />
              </button>
            </div>
            <div class="modal-content operation-form">
              <label for="copy-path-value">{fallbackLabel}</label>
              {multiline ? (
                <textarea
                  ref={fallbackInput}
                  id="copy-path-value"
                  class="copy-fallback-text"
                  value={value}
                  readOnly
                  rows={12}
                  onFocus={(event) => event.currentTarget.select()}
                />
              ) : (
                <input
                  ref={fallbackInput}
                  id="copy-path-value"
                  value={value}
                  readOnly
                  onFocus={(event) => event.currentTarget.select()}
                />
              )}
              <div class="dialog-actions">
                <button
                  class="button button-primary"
                  type="button"
                  onClick={() => setShowFallback(false)}
                >
                  Done
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}
