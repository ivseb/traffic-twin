// Svelte action for overflow containers (wide tables, code): a region that scrolls must be reachable
// with the keyboard (WCAG 2.1.1), otherwise someone who cannot use a pointer cannot read its end.
// The element becomes focusable only while its content really overflows, so there are no needless tab
// stops; with a `label` it is also exposed as a named group.

export function scrollable(node: HTMLElement, label?: string): { update: (l?: string) => void; destroy: () => void } {
  const apply = (): void => {
    const overflows = node.scrollWidth > node.clientWidth || node.scrollHeight > node.clientHeight;
    if (overflows) {
      node.tabIndex = 0;
      if (label) {
        node.setAttribute('role', 'group');
        node.setAttribute('aria-label', label);
      }
    } else {
      node.removeAttribute('tabindex');
      node.removeAttribute('role');
      node.removeAttribute('aria-label');
    }
  };
  // The box itself changes with the viewport, its content (a table) with the text and the fonts.
  const ro = new ResizeObserver(apply);
  const watch = (): void => {
    ro.disconnect();
    ro.observe(node);
    for (const c of node.children) ro.observe(c);
  };
  const mo = new MutationObserver(() => {
    watch();
    apply();
  });
  mo.observe(node, { childList: true, subtree: true, characterData: true });
  watch();
  apply();
  return {
    update(l) {
      label = l;
      apply();
    },
    destroy() {
      ro.disconnect();
      mo.disconnect();
    },
  };
}
