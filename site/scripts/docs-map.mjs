// Shared description of the Italian reference documentation that is generated
// from the repository's Markdown files (see sync-docs.mjs). The VitePress
// config imports it to build the sidebar, so the page list lives in one place.
//
// Only Node built-ins: the site has no dependencies besides VitePress.

import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

export const SITE_DIR = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
export const REPO_ROOT = path.resolve(SITE_DIR, '..')

// Where the generated pages go, relative to the site directory. The whole
// folder is generated and gitignored.
export const OUT_DIR = 'it/docs'

export const GITHUB_REPO = 'https://github.com/ivseb/traffic-twin'
export const GITHUB_BRANCH = 'main'

// Sidebar groups, in display order. Each known page has a short Italian
// label; a Markdown file added later to docs/ or docs/spec/ is picked up
// automatically and lands in its directory's group with its H1 as label.
const GROUPS = [
  { key: 'start', text: 'Per iniziare' },
  { key: 'design', text: 'Architettura e sicurezza' },
  { key: 'ops', text: 'Operazioni' },
  { key: 'spec', text: 'Specifiche' },
  { key: 'project', text: 'Progetto' }
]

const KNOWN = {
  'docs/GETTING_STARTED.md': { group: 'start', label: 'Primo giro in 15 minuti' },
  'docs/USER_GUIDE.md': { group: 'start', label: 'Manuale utente' },
  'docs/ARCHITECTURE.md': { group: 'design', label: 'Architettura' },
  'docs/THREAT_MODEL.md': { group: 'design', label: 'Threat model' },
  'docs/OPERATIONS.md': { group: 'ops', label: 'Guida operativa' },
  'docs/DATA_LIFECYCLE.md': { group: 'ops', label: 'Ciclo di vita dei dati' },
  'docs/PERFORMANCE.md': { group: 'ops', label: 'Prestazioni' },
  'docs/spec/README.md': { group: 'spec', label: 'Indice e changelog' },
  'docs/spec/sanitizer.md': { group: 'spec', label: 'Sanitizer' },
  'docs/spec/policy.md': { group: 'spec', label: 'Policy' },
  'docs/spec/event.md': { group: 'spec', label: 'Evento' },
  'docs/spec/rules.md': { group: 'spec', label: 'Regole' },
  'docs/spec/pack.md': { group: 'spec', label: 'Pacchetto twin' },
  'docs/spec/mock.md': { group: 'spec', label: 'Mock con stato' },
  'docs/spec/keyguard.md': { group: 'spec', label: 'Keyguard' },
  'docs/spec/hardening.md': { group: 'spec', label: 'Rafforzamenti' },
  'RELEASING.md': { group: 'project', label: 'Come si rilascia' },
  'SECURITY.md': { group: 'project', label: 'Security policy (EN)' },
  'CONTRIBUTING.md': { group: 'project', label: 'Contributing (EN)' }
}

const ROOT_FILES = ['RELEASING.md', 'SECURITY.md', 'CONTRIBUTING.md']

// docs/GETTING_STARTED.md -> getting-started.md, docs/spec/README.md -> spec/index.md
function outName(src) {
  const rel = src.startsWith('docs/') ? src.slice('docs/'.length) : src
  const dir = path.posix.dirname(rel)
  let base = path.posix.basename(rel, '.md')
  base = base === 'README' ? 'index' : base.toLowerCase().replace(/_/g, '-')
  return dir === '.' ? `${base}.md` : `${dir}/${base}.md`
}

function h1(file) {
  const m = fs.readFileSync(file, 'utf8').match(/^# (.+)$/m)
  return m ? m[1].replace(/^traffic-twin\s*[—:-]\s*/, '').replace(/`/g, '').trim() : path.basename(file)
}

function listMd(dir) {
  const abs = path.join(REPO_ROOT, dir)
  if (!fs.existsSync(abs)) return []
  return fs
    .readdirSync(abs)
    .filter((f) => f.endsWith('.md'))
    .sort()
    .map((f) => `${dir}/${f}`)
}

// Every page to generate: { src, out, label, group }. `src` is repository
// relative, `out` relative to OUT_DIR.
export function docPages() {
  const sources = [...listMd('docs'), ...listMd('docs/spec'), ...ROOT_FILES.filter((f) => fs.existsSync(path.join(REPO_ROOT, f)))]
  const order = Object.keys(KNOWN)
  return sources
    .map((src) => {
      const known = KNOWN[src]
      const group = known ? known.group : src.startsWith('docs/spec/') ? 'spec' : src.startsWith('docs/') ? 'ops' : 'project'
      return { src, out: outName(src), label: known ? known.label : h1(path.join(REPO_ROOT, src)), group }
    })
    .sort((a, b) => {
      const ia = order.indexOf(a.src)
      const ib = order.indexOf(b.src)
      return (ia < 0 ? order.length : ia) - (ib < 0 ? order.length : ib) || a.src.localeCompare(b.src)
    })
}

// Sidebar for the Italian locale, built from docPages().
export function italianSidebar() {
  const pages = docPages()
  return GROUPS.map((g) => ({
    text: g.text,
    collapsed: false,
    items: pages
      .filter((p) => p.group === g.key)
      .map((p) => ({ text: p.label, link: `/${OUT_DIR}/${p.out.replace(/(^|\/)index\.md$/, '$1').replace(/\.md$/, '')}` }))
  })).filter((g) => g.items.length > 0)
}
