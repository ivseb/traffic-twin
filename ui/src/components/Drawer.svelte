<script lang="ts">
  import type { Snippet } from 'svelte';
  import Modal from './Modal.svelte';

  let { open = $bindable(), title, children, footer, onclose }: { open: boolean; title: string; children: Snippet; footer?: Snippet; onclose?: () => void } = $props();
</script>

<Modal bind:open {title} {footer} {onclose} variant="drawer">{@render children()}</Modal>
