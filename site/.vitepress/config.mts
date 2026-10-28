import { defineConfig, type DefaultTheme } from 'vitepress'
import { italianSidebar } from '../scripts/docs-map.mjs'

const REPO = 'https://github.com/ivseb/traffic-twin'
const BASE = '/traffic-twin/'

// GitHub-compatible heading ids, so the anchors written in docs/*.md for
// GitHub (e.g. `#2-dimensionamento`) keep working on the site.
function githubSlug(text: string): string {
  return text
    .trim()
    .toLowerCase()
    .replace(/[^\p{L}\p{M}\p{N}\s_-]/gu, '')
    .replace(/\s/g, '-')
}

const englishSidebar: DefaultTheme.SidebarItem[] = [
  {
    text: 'Guide',
    items: [
      { text: 'Getting started', link: '/guide/getting-started' },
      { text: 'Architecture overview', link: '/guide/architecture' },
      { text: 'Security model', link: '/guide/security' },
      { text: 'SDKs', link: '/guide/sdks' },
      { text: 'Operations summary', link: '/guide/operations' }
    ]
  },
  {
    text: 'Full reference (Italian)',
    collapsed: true,
    items: italianSidebar().flatMap((g) => g.items as DefaultTheme.SidebarItem[])
  }
]

export default defineConfig({
  base: BASE,
  title: 'traffic-twin',
  cleanUrls: true,
  lastUpdated: false,
  appearance: true,
  srcExclude: ['**/README.txt', 'node_modules/**'],
  // The Italian local-search index covers ~7,000 lines of reference docs and
  // is loaded only when search is opened; it is expected to be large.
  vite: { build: { chunkSizeWarningLimit: 1024 } },
  head: [
    ['link', { rel: 'icon', type: 'image/svg+xml', href: `${BASE}logo.svg` }],
    ['meta', { name: 'theme-color', content: '#0f766e' }],
    ['meta', { name: 'referrer', content: 'no-referrer' }]
  ],
  markdown: {
    anchor: { slugify: githubSlug },
    config(md) {
      // Inline code is never Vue template: `{{baseUrl}}` must stay literal.
      const codeInline = md.renderer.rules.code_inline!
      md.renderer.rules.code_inline = (tokens, idx, options, env, self) =>
        codeInline(tokens, idx, options, env, self).replace(/^<code/, '<code v-pre')
    }
  },
  locales: {
    root: {
      label: 'English',
      lang: 'en',
      description:
        'traffic-twin observes production HTTP traffic without ever exporting real values, infers contracts and cause → effect rules, and builds a stateful mock populated with synthetic customers.',
      themeConfig: {
        nav: [
          { text: 'Guide', link: '/guide/getting-started', activeMatch: '^/guide/' },
          { text: 'Reference (IT)', link: '/it/docs/getting-started', activeMatch: '^/it/docs/' },
          {
            text: 'v0.1.0',
            items: [
              { text: 'Releases', link: `${REPO}/releases` },
              { text: 'Security policy', link: '/it/docs/security' },
              { text: 'Contributing', link: '/it/docs/contributing' }
            ]
          }
        ],
        sidebar: {
          '/guide/': englishSidebar
        },
        editLink: { text: 'Edit this page on GitHub', pattern: editLinkPattern },
        footer: {
          message: 'Released under the Apache License 2.0. No trackers, no analytics, no third-party requests.',
          copyright: 'traffic-twin contributors'
        }
      }
    },
    it: {
      label: 'Italiano',
      lang: 'it',
      link: '/it/',
      description:
        'traffic-twin osserva il traffico HTTP di produzione senza mai portare fuori i valori veri, ne ricava contratti e regole causa → effetto e produce un mock con stato popolato da clienti sintetici.',
      themeConfig: {
        nav: [
          { text: 'Documentazione', link: '/it/docs/getting-started', activeMatch: '^/it/docs/' },
          { text: 'Specifiche', link: '/it/docs/spec/', activeMatch: '^/it/docs/spec/' },
          {
            text: 'v0.1.0',
            items: [
              { text: 'Release', link: `${REPO}/releases` },
              { text: 'Sicurezza', link: '/it/docs/security' },
              { text: 'Contribuire', link: '/it/docs/contributing' }
            ]
          }
        ],
        sidebar: {
          '/it/docs/': italianSidebar()
        },
        editLink: { text: 'Modifica la fonte su GitHub', pattern: editLinkPattern },
        outline: { level: [2, 3], label: 'In questa pagina' },
        docFooter: { prev: 'Pagina precedente', next: 'Pagina successiva' },
        darkModeSwitchLabel: 'Aspetto',
        lightModeSwitchTitle: 'Passa al tema chiaro',
        darkModeSwitchTitle: 'Passa al tema scuro',
        sidebarMenuLabel: 'Menu',
        returnToTopLabel: 'Torna su',
        langMenuLabel: 'Cambia lingua',
        notFound: {
          title: 'PAGINA NON TROVATA',
          quote: 'Questa pagina non esiste o è stata spostata.',
          linkLabel: 'Vai alla home',
          linkText: 'Torna alla home'
        },
        footer: {
          message: 'Rilasciato con licenza Apache 2.0. Nessun tracker, nessuna analisi, nessuna richiesta a terzi.',
          copyright: 'Autori di traffic-twin'
        }
      }
    }
  },
  themeConfig: {
    logo: { src: '/logo.svg', alt: '' },
    siteTitle: 'traffic-twin',
    // The English guide and the Italian reference are different pages, not
    // translations of each other: the language menu goes to the locale's home.
    i18nRouting: false,
    outline: { level: [2, 3] },
    socialLinks: [{ icon: 'github', link: REPO, ariaLabel: 'traffic-twin on GitHub' }],
    externalLinkIcon: true,
    search: {
      provider: 'local',
      options: {
        locales: {
          it: {
            translations: {
              button: { buttonText: 'Cerca', buttonAriaLabel: 'Cerca' },
              modal: {
                displayDetails: 'Mostra dettagli',
                resetButtonTitle: 'Cancella la ricerca',
                backButtonTitle: 'Chiudi la ricerca',
                noResultsText: 'Nessun risultato per',
                footer: {
                  selectText: 'per scegliere',
                  selectKeyAriaLabel: 'invio',
                  navigateText: 'per spostarti',
                  navigateUpKeyAriaLabel: 'freccia su',
                  navigateDownKeyAriaLabel: 'freccia giù',
                  closeText: 'per chiudere',
                  closeKeyAriaLabel: 'esc'
                }
              }
            }
          }
        }
      }
    }
  }
})

// Generated reference pages carry `source:` front matter (the file in the
// repository they were copied from); every other page lives under site/.
// This function is serialized to the client, so it must be self-contained.
function editLinkPattern(page: { filePath: string; frontmatter: Record<string, any> }): string {
  const repo = 'https://github.com/ivseb/traffic-twin/edit/main/'
  return page.frontmatter.source ? repo + page.frontmatter.source : `${repo}site/${page.filePath}`
}
