<script setup lang="ts">
// The traffic-twin pipeline across the three trust zones, as inline SVG.
// Two layouts of the same content: horizontal (wide screens) and vertical
// (phones); CSS shows one of them. Labels are localized through `lang`.
import { computed, useId } from 'vue'

const props = defineProps<{ lang?: 'en' | 'it' }>()
const uid = useId()

const TEXT = {
  en: {
    title: 'The traffic-twin pipeline',
    desc:
      'Five steps across three trust zones. Zone A, inside the application: observe and sanitize; real values exist only here. ' +
      'Check 1, the mTLS intake, accepts only shapes, HMAC tokens and values the signed policy allows. ' +
      'Zone B, tt-core: infer OpenAPI contracts and cause-effect rules, then build a synthetic world from k-anonymous archetypes. ' +
      'Check 2, the publication gate, verified and signed by keyguard. Zone C, development and CI: a signed twin pack served by a stateful mock.',
    zones: [
      { name: 'Zone A · inside the app', sub: 'real values, for one call' },
      { name: 'Zone B · tt-core', sub: 'shapes and HMAC tokens, no keys' },
      { name: 'Zone C · dev / CI', sub: 'synthetic data only' }
    ],
    steps: [
      { t: 'Observe', d: ['SDK or tt-egress', 'in the app process'] },
      { t: 'Sanitize', d: ['signed policy,', 'deny-by-default'] },
      { t: 'Infer', d: ['OpenAPI contracts,', 'cause → effect rules'] },
      { t: 'Synthesize', d: ['k-anonymous archetypes', '→ synthetic world'] },
      { t: 'Mock', d: ['signed twin pack,', 'stateful mock'] }
    ],
    checks: ['check 1: mTLS intake', 'check 2: gate + keyguard signature']
  },
  it: {
    title: 'La pipeline di traffic-twin',
    desc:
      "Cinque passi in tre zone di fiducia. Zona A, dentro l'applicazione: osserva e sanifica; i valori veri esistono solo qui. " +
      "Controllo 1, l'intake su mTLS, accetta solo forme, token HMAC e valori ammessi dalla policy firmata. " +
      'Zona B, tt-core: ricava contratti OpenAPI e regole causa-effetto, poi costruisce un mondo sintetico da archetipi k-anonimi. ' +
      'Controllo 2, il gate di pubblicazione, verificato e firmato da keyguard. Zona C, sviluppo e CI: un pacchetto twin firmato servito da un mock con stato.',
    zones: [
      { name: "Zona A · dentro l'app", sub: 'valori veri, per una chiamata' },
      { name: 'Zona B · tt-core', sub: 'forme e token HMAC, nessuna chiave' },
      { name: 'Zona C · dev / CI', sub: 'solo dati sintetici' }
    ],
    steps: [
      { t: 'Osserva', d: ['SDK o tt-egress', "nel processo dell'app"] },
      { t: 'Sanifica', d: ['policy firmata,', 'deny-by-default'] },
      { t: 'Ricava', d: ['contratti OpenAPI,', 'regole causa → effetto'] },
      { t: 'Sintetizza', d: ['archetipi k-anonimi', '→ mondo sintetico'] },
      { t: 'Mock', d: ['pacchetto firmato,', 'mock con stato'] }
    ],
    checks: ['controllo 1: intake mTLS', 'controllo 2: gate + firma keyguard']
  }
}

const t = computed(() => TEXT[props.lang ?? 'en'])

// Horizontal layout: 1000 x 250.
const H = {
  zones: [
    { x: 0, w: 390 },
    { x: 400, w: 390 },
    { x: 800, w: 200 }
  ],
  boxes: [16, 208, 416, 608, 816].map((x) => ({ x, y: 78, w: 168, h: 92 })),
  zoneOf: [0, 0, 1, 1, 2]
}

// Vertical layout: 360 x 666. The check labels sit in the gaps between zones.
const V = {
  zones: [
    { y: 0, h: 230 },
    { y: 262, h: 232 },
    { y: 526, h: 140 }
  ],
  boxes: [56, 140, 318, 402, 582].map((y) => ({ x: 30, y, w: 300, h: 64 }))
}
</script>

<template>
  <figure class="tt-pipeline">
    <!-- wide screens -->
    <svg
      class="tt-pipeline-h"
      viewBox="0 0 1000 250"
      role="img"
      :aria-labelledby="`${uid}-h-title ${uid}-h-desc`"
    >
      <title :id="`${uid}-h-title`">{{ t.title }}</title>
      <desc :id="`${uid}-h-desc`">{{ t.desc }}</desc>
      <defs>
        <marker :id="`${uid}-h-arrow`" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 10 5 0 10z" class="tt-arrowhead" />
        </marker>
      </defs>
      <g v-for="(z, i) in H.zones" :key="`hz${i}`">
        <rect :x="z.x" y="0" :width="z.w" height="250" rx="14" :class="`tt-zone tt-zone-${i}`" />
        <text :x="z.x + z.w / 2" y="30" class="tt-zone-name" text-anchor="middle">{{ t.zones[i].name }}</text>
        <text :x="z.x + z.w / 2" y="50" class="tt-zone-sub" text-anchor="middle">{{ t.zones[i].sub }}</text>
      </g>
      <g v-for="(b, i) in H.boxes" :key="`hb${i}`">
        <rect :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="10" class="tt-box" />
        <text :x="b.x + b.w / 2" :y="b.y + 32" class="tt-box-title" text-anchor="middle">{{ t.steps[i].t }}</text>
        <text :x="b.x + b.w / 2" :y="b.y + 56" class="tt-box-desc tt-box-desc-h" text-anchor="middle">{{ t.steps[i].d[0] }}</text>
        <text :x="b.x + b.w / 2" :y="b.y + 74" class="tt-box-desc tt-box-desc-h" text-anchor="middle">{{ t.steps[i].d[1] }}</text>
      </g>
      <line
        v-for="i in 4"
        :key="`ha${i}`"
        :x1="H.boxes[i - 1].x + H.boxes[i - 1].w + 2"
        :x2="H.boxes[i].x - 3"
        y1="124"
        y2="124"
        :class="i === 2 || i === 4 ? 'tt-arrow tt-arrow-check' : 'tt-arrow'"
        :marker-end="`url(#${uid}-h-arrow)`"
      />
      <text x="395" y="208" class="tt-check" text-anchor="middle">{{ t.checks[0] }}</text>
      <text x="795" y="208" class="tt-check" text-anchor="end">{{ t.checks[1] }}</text>
      <circle cx="395" cy="124" r="5" class="tt-check-dot" />
      <circle cx="795" cy="124" r="5" class="tt-check-dot" />
    </svg>

    <!-- phones -->
    <svg
      class="tt-pipeline-v"
      viewBox="0 0 360 666"
      role="img"
      :aria-labelledby="`${uid}-v-title ${uid}-v-desc`"
    >
      <title :id="`${uid}-v-title`">{{ t.title }}</title>
      <desc :id="`${uid}-v-desc`">{{ t.desc }}</desc>
      <defs>
        <marker :id="`${uid}-v-arrow`" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">
          <path d="M0 0 10 5 0 10z" class="tt-arrowhead" />
        </marker>
      </defs>
      <g v-for="(z, i) in V.zones" :key="`vz${i}`">
        <rect x="0" :y="z.y" width="360" :height="z.h" rx="14" :class="`tt-zone tt-zone-${i}`" />
        <text x="180" :y="z.y + 24" class="tt-zone-name" text-anchor="middle">{{ t.zones[i].name }}</text>
        <text x="180" :y="z.y + 42" class="tt-zone-sub" text-anchor="middle">{{ t.zones[i].sub }}</text>
      </g>
      <g v-for="(b, i) in V.boxes" :key="`vb${i}`">
        <rect :x="b.x" :y="b.y" :width="b.w" :height="b.h" rx="10" class="tt-box" />
        <text x="180" :y="b.y + 26" class="tt-box-title" text-anchor="middle">{{ t.steps[i].t }}</text>
        <text x="180" :y="b.y + 48" class="tt-box-desc" text-anchor="middle">{{ t.steps[i].d.join(' ') }}</text>
      </g>
      <line
        v-for="i in 4"
        :key="`va${i}`"
        x1="60"
        x2="60"
        :y1="V.boxes[i - 1].y + V.boxes[i - 1].h + 2"
        :y2="V.boxes[i].y - 3"
        :class="i === 2 || i === 4 ? 'tt-arrow tt-arrow-check' : 'tt-arrow'"
        :marker-end="`url(#${uid}-v-arrow)`"
      />
      <circle cx="60" cy="246" r="5" class="tt-check-dot" />
      <circle cx="60" cy="510" r="5" class="tt-check-dot" />
      <text x="74" y="251" class="tt-check">{{ t.checks[0] }}</text>
      <text x="74" y="515" class="tt-check">{{ t.checks[1] }}</text>
    </svg>
  </figure>
</template>

<style scoped>
.tt-pipeline {
  margin: 24px 0 8px;
}
.tt-pipeline svg {
  width: 100%;
  height: auto;
  display: block;
  font-family: var(--vp-font-family-base);
}
.tt-pipeline-v {
  display: none !important;
  max-width: 420px;
  margin: 0 auto;
}
@media (max-width: 767px) {
  .tt-pipeline-h {
    display: none !important;
  }
  .tt-pipeline-v {
    display: block !important;
  }
}
.tt-zone-0 {
  fill: var(--vp-c-yellow-soft);
}
.tt-zone-1 {
  fill: var(--vp-c-indigo-soft);
}
.tt-zone-2 {
  fill: var(--vp-c-green-soft);
}
.tt-zone-name {
  fill: var(--vp-c-text-1);
  font-size: 15px;
  font-weight: 700;
}
.tt-zone-sub {
  fill: var(--vp-c-text-2);
  font-size: 13px;
}
.tt-box {
  fill: var(--vp-c-bg);
  stroke: var(--vp-c-border);
  stroke-width: 1.5;
}
.tt-box-title {
  fill: var(--vp-c-text-1);
  font-size: 17px;
  font-weight: 700;
}
.tt-box-desc {
  fill: var(--vp-c-text-2);
  font-size: 13px;
}
.tt-box-desc-h {
  font-size: 12.5px;
}
.tt-arrow {
  stroke: var(--vp-c-text-2);
  stroke-width: 2;
}
.tt-arrow-check {
  stroke: var(--vp-c-brand-1);
  stroke-width: 2.5;
}
.tt-arrowhead {
  fill: var(--vp-c-text-2);
}
.tt-check {
  fill: var(--vp-c-brand-1);
  font-size: 13px;
  font-weight: 600;
}
.tt-check-dot {
  fill: var(--vp-c-brand-1);
}
</style>
