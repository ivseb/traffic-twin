// The variant without the bundled Inter web font: the site uses system fonts.
import DefaultTheme from 'vitepress/theme-without-fonts'
import type { Theme } from 'vitepress'
import PipelineDiagram from './PipelineDiagram.vue'
import Mermaid from './Mermaid.vue'
import './custom.css'

export default {
  extends: DefaultTheme,
  enhanceApp({ app }) {
    app.component('PipelineDiagram', PipelineDiagram)
    app.component('Mermaid', Mermaid)
  }
} satisfies Theme
