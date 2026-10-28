<script setup lang="ts">
// Renders a ```mermaid fence in the browser. Mermaid is bundled with the site
// (no CDN) and loaded only on pages that have a diagram; the source stays
// visible as a code block until the drawing is ready or if it fails.
// Wide diagrams keep a readable size and scroll sideways; "full screen" opens
// them in a dialog at their natural size.
import { onMounted, ref, watch } from 'vue'
import { useData } from 'vitepress'

const props = defineProps<{ code: string }>()
const source = decodeURIComponent(props.code)
const svg = ref('')
const failed = ref(false)
const natural = ref(0)
const dialog = ref<HTMLDialogElement>()
const { isDark, lang } = useData()
let seq = 0

// Below this width the labels of a scaled-down diagram become too small to read.
const MIN_READABLE = 860

async function draw() {
  try {
    const { default: mermaid } = await import('mermaid')
    mermaid.initialize({
      startOnLoad: false,
      securityLevel: 'strict',
      theme: isDark.value ? 'dark' : 'default',
      // The real font of the page: with 'inherit' Mermaid measures labels in
      // one font and draws them in another, and clips them.
      fontFamily: getComputedStyle(document.body).fontFamily
    })
    const id = `mermaid-${Math.random().toString(36).slice(2)}-${seq++}`
    const out = (await mermaid.render(id, source)).svg
    const m = /max-width:\s*([\d.]+)px/.exec(out)
    natural.value = m ? Math.ceil(parseFloat(m[1])) : 0
    svg.value = out
    failed.value = false
  } catch {
    failed.value = true
  }
}

function width(): string | undefined {
  // Narrow diagrams: natural size. Wide ones: at least MIN_READABLE (or the
  // natural size if smaller), scrolling inside the box when the column is narrower.
  if (!natural.value) return undefined
  return `min(${natural.value}px, max(100%, ${MIN_READABLE}px))`
}

function open() {
  dialog.value?.showModal()
}

onMounted(draw)
watch(isDark, draw)
</script>

<template>
  <figure v-if="svg && !failed" class="tt-mermaid">
    <div class="tt-mermaid-scroll" tabindex="0" :aria-label="lang === 'it-IT' || lang === 'it' ? 'Diagramma (scorre in orizzontale)' : 'Diagram (scrolls horizontally)'">
      <div class="tt-mermaid-svg" :style="{ width: width() }" v-html="svg" />
    </div>
    <button v-if="natural > MIN_READABLE" type="button" class="tt-mermaid-full" @click="open">
      {{ lang === 'it-IT' || lang === 'it' ? 'Schermo intero' : 'Full screen' }}
    </button>
    <dialog ref="dialog" class="tt-mermaid-dialog" @click.self="dialog?.close()">
      <button type="button" class="tt-mermaid-close" @click="dialog?.close()">
        {{ lang === 'it-IT' || lang === 'it' ? 'Chiudi' : 'Close' }}
      </button>
      <div class="tt-mermaid-svg" :style="{ width: natural ? natural + 'px' : undefined }" v-html="svg" />
    </dialog>
  </figure>
  <div v-else class="language-mermaid"><pre><code>{{ source }}</code></pre></div>
</template>

<style scoped>
.tt-mermaid {
  margin: 16px 0;
}
.tt-mermaid-scroll {
  overflow-x: auto;
  border: 1px solid var(--vp-c-divider);
  border-radius: 8px;
  padding: 12px;
  background: var(--vp-c-bg-soft);
}
.tt-mermaid-svg {
  margin: 0 auto;
  max-width: none;
}
.tt-mermaid-svg :deep(svg) {
  width: 100% !important;
  max-width: none !important;
  height: auto;
}
/* The doc styles (p margins, 28px line height) leak into the HTML labels and
   overflow the boxes Mermaid measured with its own metrics. */
.tt-mermaid-svg :deep(foreignObject) :is(p, div, span) {
  margin: 0 !important;
  line-height: 1.5 !important;
}
.tt-mermaid-full {
  margin-top: 6px;
  font-size: 13px;
  color: var(--vp-c-brand-1);
  text-decoration: underline;
}
.tt-mermaid-dialog {
  width: 96vw;
  max-width: 96vw;
  height: 92vh;
  max-height: 92vh;
  padding: 16px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 10px;
  background: var(--vp-c-bg);
  color: var(--vp-c-text-1);
  overflow: auto;
}
.tt-mermaid-dialog::backdrop {
  background: rgba(0, 0, 0, 0.6);
}
.tt-mermaid-close {
  position: sticky;
  top: 0;
  left: 0;
  margin-bottom: 8px;
  padding: 4px 12px;
  border: 1px solid var(--vp-c-divider);
  border-radius: 6px;
  background: var(--vp-c-bg-soft);
}
</style>
