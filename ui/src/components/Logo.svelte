<script lang="ts">
  let { size = 28 }: { size?: number } = $props();
</script>

<svg width={size} height={size} viewBox="0 0 32 32" aria-hidden="true" focusable="false">
  <circle cx="12" cy="16" r="9" fill="none" stroke="var(--accent)" stroke-width="2.6" />
  <circle cx="20" cy="16" r="9" fill="none" stroke="var(--success)" stroke-width="2.6" />
</svg>
