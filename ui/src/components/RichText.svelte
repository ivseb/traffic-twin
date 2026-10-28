<script lang="ts">
  import { rich } from '../lib/help/index.svelte';
  let { text }: { text: string } = $props();
  const segs = $derived(rich(text));
</script>

{#each segs as s, i (i)}{#if s.t === 'text'}{s.v}{:else if s.t === 'b'}<b>{s.v}</b>{:else}<a class="gloss" href="#/glossary?term={s.id}">{s.v}</a>{/if}{/each}

<style>
  .gloss { text-decoration: underline dotted; text-underline-offset: 3px; }
</style>
