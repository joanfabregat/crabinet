import { type JSX } from "preact";
import { Check, Copy, X } from "lucide-preact";
import { useEffect, useRef, useState } from "preact/hooks";

export function CopyPathButton({
  value,
  label,
  className = "icon-button",
  size = 19,
  text,
  role,
}: {
  value: string;
  label: string;
  className?: string;
  size?: number;
  /** A visible label, for menus; icon-only buttons use a tooltip instead. */
  text?: string;
  role?: JSX.AriaRole;
}) {
  const [copied, setCopied] = useState(false);
  const [showFallback, setShowFallback] = useState(false);
  const fallbackInput = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (showFallback) {
      fallbackInput.current?.focus();
      fallbackInput.current?.select();
    }
  }, [showFallback]);

  const copy = async () => {
    try {
      if (!navigator.clipboard?.writeText)
        throw new Error("clipboard unavailable");
      await navigator.clipboard.writeText(value);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1600);
    } catch {
      setShowFallback(true);
    }
  };

  return (
    <>
      <button
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
      <span class="sr-only" role="status" aria-live="polite">
        {copied ? `Copied ${value}` : ""}
      </span>
      {showFallback && (
        <div class="modal-backdrop copy-fallback-backdrop">
          <div
            class="modal-panel copy-fallback"
            role="dialog"
            aria-modal="true"
            aria-labelledby="copy-path-title"
          >
            <div class="modal-header">
              <h2 id="copy-path-title">Copy full path</h2>
              <button
                class="modal-close"
                type="button"
                aria-label="Close copy full path"
                onClick={() => setShowFallback(false)}
              >
                <X size={20} aria-hidden="true" />
              </button>
            </div>
            <div class="modal-content operation-form">
              <label for="copy-path-value">Select and copy this path</label>
              <input
                ref={fallbackInput}
                id="copy-path-value"
                value={value}
                readOnly
                onFocus={(event) => event.currentTarget.select()}
              />
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
