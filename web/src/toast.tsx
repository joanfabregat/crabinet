import { createContext, type ComponentChildren } from "preact";
import {
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
} from "preact/hooks";
import { CircleAlert, CircleCheck, TriangleAlert, X } from "lucide-preact";

export type ToastTone = "success" | "warning" | "error";

const toneIcons = {
  success: CircleCheck,
  warning: TriangleAlert,
  error: CircleAlert,
};

export interface ToastOptions {
  /** Colours the toast; defaults to success. */
  tone?: ToastTone;
  /** One action, such as Undo, shown as a button in the toast. */
  action?: { label: string; onClick: () => void };
  /** How long the toast stays up while not hovered or focused. */
  durationMs?: number;
}

interface Toast extends ToastOptions {
  id: number;
  message: string;
}

type ShowToast = (message: string, options?: ToastOptions) => void;

const defaultDurationMs = 4_000;
// A toast with an action stays longer, so there is time to reach it.
const actionDurationMs = 12_000;
// Older toasts give way once this many are shown.
const maxToasts = 3;

const ToastContext = createContext<ShowToast>(() => {});

/** Shows a short confirmation that disappears on its own. */
export function useToast(): ShowToast {
  return useContext(ToastContext);
}

export function ToastProvider({ children }: { children: ComponentChildren }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(0);

  const show = useCallback<ShowToast>((message, options = {}) => {
    const id = ++nextId.current;
    setToasts((current) =>
      [...current, { ...options, id, message }].slice(-maxToasts),
    );
  }, []);

  const dismiss = useCallback((id: number) => {
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  return (
    <ToastContext.Provider value={show}>
      {children}
      {/* Always mounted, so screen readers announce toasts added to it. */}
      <div class="toast-region" role="status" aria-live="polite">
        {toasts.map((toast) => (
          <ToastItem key={toast.id} toast={toast} onDismiss={dismiss} />
        ))}
      </div>
    </ToastContext.Provider>
  );
}

function ToastItem({
  toast,
  onDismiss,
}: {
  toast: Toast;
  onDismiss: (id: number) => void;
}) {
  const [paused, setPaused] = useState({ hover: false, focus: false });
  const remaining = useRef(
    toast.durationMs ??
      // A problem, or an action to reach, needs more reading time.
      (toast.action || toast.tone === "error"
        ? actionDurationMs
        : defaultDurationMs),
  );
  const tone = toast.tone ?? "success";
  const Icon = toneIcons[tone];
  const running = !paused.hover && !paused.focus;

  useEffect(() => {
    if (!running) return;
    const startedAt = Date.now();
    const timer = window.setTimeout(
      () => onDismiss(toast.id),
      remaining.current,
    );
    return () => {
      window.clearTimeout(timer);
      remaining.current = Math.max(
        0,
        remaining.current - (Date.now() - startedAt),
      );
    };
  }, [onDismiss, running, toast.id]);

  return (
    <div
      class={`toast toast-${tone}`}
      onMouseEnter={() => setPaused((value) => ({ ...value, hover: true }))}
      onMouseLeave={() => setPaused((value) => ({ ...value, hover: false }))}
      onFocusIn={() => setPaused((value) => ({ ...value, focus: true }))}
      onFocusOut={(event) => {
        if (!event.currentTarget.contains(event.relatedTarget as Node | null))
          setPaused((value) => ({ ...value, focus: false }));
      }}
    >
      <Icon class="toast-icon" size={20} aria-hidden="true" />
      <span class="toast-message">{toast.message}</span>
      {toast.action && (
        <button
          type="button"
          class="button button-secondary"
          onClick={() => {
            onDismiss(toast.id);
            toast.action?.onClick();
          }}
        >
          {toast.action.label}
        </button>
      )}
      <button
        type="button"
        class="toast-close"
        aria-label="Dismiss notification"
        onClick={() => onDismiss(toast.id)}
      >
        <X size={16} aria-hidden="true" />
      </button>
    </div>
  );
}
