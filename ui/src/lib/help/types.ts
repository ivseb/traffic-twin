// Structured help content (Italian + English). Texts use a tiny markup:
//   [[glossary-id]]            link to the glossary entry (label = its term)
//   [[glossary-id|label]]      link with a custom label
//   **bold**                   emphasis
// Keeping content in plain data files makes it easy to review without reading UI code.

export interface FieldHelp {
  /** Short label of the thing being explained. */
  title: string;
  /** What it is, for someone who has never seen the product. */
  meaning: string;
  /** What changes in practice when you act on it. */
  effect?: string;
  default?: string;
  /** When it makes sense to change it. */
  when?: string;
  /** A concrete example. */
  example?: string;
  /** Glossary entry to open for the full explanation. */
  term?: string;
}

export interface PageGuide {
  title: string;
  /** What the page is for, in one or two sentences. */
  purpose: string;
  /** How to use it, step by step. */
  steps: string[];
  /** Concepts shown on the page, each with a short plain explanation. */
  concepts: { term: string; text: string }[];
  /** Practical consequences of the actions available here. */
  effects: string[];
  /** Short text of the first-visit hint. */
  firstVisit: string;
}

export interface GlossaryEntry {
  term: string;
  short: string;
  long: string;
  example?: string;
  see?: string[];
}

export interface HelpPack {
  pages: Record<string, PageGuide>;
  fields: Record<string, FieldHelp>;
  glossary: Record<string, GlossaryEntry>;
  ui: Record<string, string>;
}
