/**
 * Scroll to an element by DOM id, open any collapsed <details> around it, focus it when it is a
 * control, and flash a highlight. The element may not exist yet (the page is still loading), so
 * this polls briefly. Returns a cancel function.
 */
const HIGHLIGHT_MS = 2000;
const POLL_MS = 50;
const GIVE_UP_MS = 3000;

export function reveal(id: string): () => void {
  let timer: number | undefined;
  const started = Date.now();
  const tick = () => {
    const el = document.getElementById(id);
    if (!el) {
      if (Date.now() - started < GIVE_UP_MS) timer = window.setTimeout(tick, POLL_MS);
      return;
    }
    for (let d = el.closest("details"); d; d = d.parentElement?.closest("details") ?? null) {
      d.open = true;
    }
    // A checkbox or number field is highlighted through its label, so the whole row lights up.
    const box = (el.closest("label") ?? el) as HTMLElement;
    box.scrollIntoView({ block: "center" });
    if (/^(INPUT|SELECT|TEXTAREA|BUTTON)$/.test(el.tagName)) (el as HTMLElement).focus({ preventScroll: true });
    box.classList.remove("search-highlight");
    void box.offsetWidth; // restart the animation when revealed twice
    box.classList.add("search-highlight");
    timer = window.setTimeout(() => box.classList.remove("search-highlight"), HIGHLIGHT_MS);
  };
  tick();
  return () => window.clearTimeout(timer);
}
