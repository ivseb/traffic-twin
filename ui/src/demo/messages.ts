// Texts that exist only in the demo build (mock adapter, one-click roles, banner).
// They are registered at start-up of the demo build; the production dictionaries do
// not contain them.

import { registerMessages, tk } from '../lib/i18n/index.svelte';

const it = {
  'demo.banner.title': 'Ambiente dimostrativo.',
  'demo.banner.hint': 'Questa interfaccia usa dati inventati in memoria, non un server reale.',
  'demo.roles': 'Demo: entra con un altro ruolo',
  'demo.login.title': 'Modalità dimostrativa',
  'demo.login.text': 'I dati sono inventati. Entra direttamente con un ruolo per vedere come cambia l’interfaccia:',
  'demo.login.creds': 'Oppure usa un utente di esempio (elena.admin, olga.operator, rita.reviewer…) con password «demo».',
  'demo.login.firstRun': 'Simula il primo avvio (setup)',
  'demo.setup.hint': 'In modalità dimostrativa il token di setup deve iniziare con «tts_».',
} as const;

const en: Record<keyof typeof it, string> = {
  'demo.banner.title': 'Demo environment.',
  'demo.banner.hint': 'This interface uses invented in-memory data, not a real server.',
  'demo.roles': 'Demo: switch to another role',
  'demo.login.title': 'Demo mode',
  'demo.login.text': 'The data is invented. Enter with a role to see how the interface changes:',
  'demo.login.creds': 'Or use a sample user (elena.admin, olga.operator, rita.reviewer…) with password “demo”.',
  'demo.login.firstRun': 'Simulate first run (setup)',
  'demo.setup.hint': 'In demo mode the setup token must start with “tts_”.',
};

export type DemoKey = keyof typeof it;

export function registerDemoMessages(): void {
  registerMessages('it', it);
  registerMessages('en', en);
}

/** Translate a demo-only key. */
export const d = (key: DemoKey): string => tk(key);
