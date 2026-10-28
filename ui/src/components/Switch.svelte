<script lang="ts">
  let { checked = $bindable(), label, disabled = false, onchange }: { checked: boolean; label: string; disabled?: boolean; onchange?: (v: boolean) => void } = $props();
</script>

<label class="sw" class:disabled>
  <input type="checkbox" role="switch" bind:checked {disabled} onchange={() => onchange?.(checked)} />
  <span class="track" aria-hidden="true"><i></i></span>
  <span>{label}</span>
</label>

<style>
  .sw { display: inline-flex; align-items: center; gap: var(--s-2); cursor: pointer; font-weight: 500; }
  .sw.disabled { opacity: 0.55; cursor: not-allowed; }
  input { position: absolute; opacity: 0; width: 1px; height: 1px; }
  .track { width: 2.4rem; height: 1.35rem; border-radius: 999px; background: var(--control-border); position: relative; transition: background 0.12s; flex: none; }
  i { position: absolute; top: 2px; left: 2px; width: calc(1.35rem - 4px); height: calc(1.35rem - 4px); border-radius: 50%; background: var(--surface); transition: transform 0.12s; box-shadow: var(--shadow-sm); }
  input:checked + .track { background: var(--accent); }
  input:checked + .track i { transform: translateX(1.05rem); }
  input:focus-visible + .track { outline: 2px solid var(--focus); outline-offset: 2px; }
</style>
