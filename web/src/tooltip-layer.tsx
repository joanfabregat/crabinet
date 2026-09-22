import { useEffect, useLayoutEffect, useRef, useState } from "preact/hooks";

interface ActiveTooltip {
  label: string;
  target: HTMLElement;
}

interface TooltipPosition {
  left: number;
  top: number;
}

const TOOLTIP_GAP = 8;
const VIEWPORT_MARGIN = 8;

function triggerFrom(value: EventTarget | null): HTMLElement | null {
  return value instanceof Element
    ? value.closest<HTMLElement>(".tooltip-action[data-tooltip]")
    : null;
}

export function TooltipLayer() {
  const [active, setActive] = useState<ActiveTooltip>();
  const [position, setPosition] = useState<TooltipPosition>();
  const tooltipRef = useRef<HTMLDivElement>(null);
  const activeTarget = active?.target;

  useEffect(() => {
    const show = (target: HTMLElement) => {
      const label = target.dataset.tooltip;
      if (!label) return;
      setPosition(undefined);
      setActive({ label, target });
    };
    const hide = (target?: HTMLElement) => {
      setActive((current) => {
        if (target && current?.target !== target) return current;
        return undefined;
      });
    };
    const pointerOver = (event: PointerEvent) => {
      const target = triggerFrom(event.target);
      if (target && triggerFrom(event.relatedTarget) !== target) show(target);
    };
    const pointerOut = (event: PointerEvent) => {
      const target = triggerFrom(event.target);
      if (target && triggerFrom(event.relatedTarget) !== target) hide(target);
    };
    const focusIn = (event: FocusEvent) => {
      const target = triggerFrom(event.target);
      if (target) show(target);
    };
    const focusOut = (event: FocusEvent) => {
      const target = triggerFrom(event.target);
      if (target && triggerFrom(event.relatedTarget) !== target) hide(target);
    };
    const keyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") hide();
    };
    const dismiss = () => hide();

    document.addEventListener("pointerover", pointerOver);
    document.addEventListener("pointerout", pointerOut);
    document.addEventListener("focusin", focusIn);
    document.addEventListener("focusout", focusOut);
    document.addEventListener("keydown", keyDown);
    document.addEventListener("scroll", dismiss, true);
    window.addEventListener("resize", dismiss);
    return () => {
      document.removeEventListener("pointerover", pointerOver);
      document.removeEventListener("pointerout", pointerOut);
      document.removeEventListener("focusin", focusIn);
      document.removeEventListener("focusout", focusOut);
      document.removeEventListener("keydown", keyDown);
      document.removeEventListener("scroll", dismiss, true);
      window.removeEventListener("resize", dismiss);
    };
  }, []);

  useEffect(() => {
    if (!activeTarget) return;
    const observer = new MutationObserver(() => {
      if (!activeTarget.isConnected) {
        setActive(undefined);
        setPosition(undefined);
        return;
      }
      const label = activeTarget.dataset.tooltip;
      if (!label) {
        setActive(undefined);
        return;
      }
      setActive((current) =>
        current?.target === activeTarget && current.label !== label
          ? { ...current, label }
          : current,
      );
    });
    observer.observe(activeTarget, {
      attributes: true,
      attributeFilter: ["data-tooltip"],
    });
    observer.observe(document.body, { childList: true, subtree: true });
    return () => observer.disconnect();
  }, [activeTarget]);

  useLayoutEffect(() => {
    const tooltip = tooltipRef.current;
    if (!active || !tooltip) return;
    if (!active.target.isConnected) {
      setActive(undefined);
      setPosition(undefined);
      return;
    }

    const targetRect = active.target.getBoundingClientRect();
    const tooltipRect = tooltip.getBoundingClientRect();
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    let left = targetRect.left + (targetRect.width - tooltipRect.width) / 2;
    left = Math.min(
      Math.max(left, VIEWPORT_MARGIN),
      Math.max(
        VIEWPORT_MARGIN,
        viewportWidth - tooltipRect.width - VIEWPORT_MARGIN,
      ),
    );

    const above = targetRect.top - tooltipRect.height - TOOLTIP_GAP;
    const below = targetRect.bottom + TOOLTIP_GAP;
    const prefersBelow = active.target.classList.contains("tooltip-below");
    let top = prefersBelow ? below : above;
    if (!prefersBelow && above < VIEWPORT_MARGIN) top = below;
    if (
      prefersBelow &&
      below + tooltipRect.height > viewportHeight - VIEWPORT_MARGIN
    ) {
      top = above;
    }
    top = Math.min(
      Math.max(top, VIEWPORT_MARGIN),
      Math.max(
        VIEWPORT_MARGIN,
        viewportHeight - tooltipRect.height - VIEWPORT_MARGIN,
      ),
    );

    setPosition({ left, top });
  }, [active]);

  if (!active) return null;

  return (
    <div
      ref={tooltipRef}
      class={`app-tooltip${position ? " is-visible" : ""}`}
      role="tooltip"
      style={{
        left: `${position?.left ?? -10_000}px`,
        top: `${position?.top ?? -10_000}px`,
      }}
    >
      {active.label}
    </div>
  );
}
