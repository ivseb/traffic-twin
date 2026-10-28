// Pure helpers of the "Formato degli id" card.

import type { IdFormatErrorCode } from './api/idfmt';

/**
 * The default synthetic id of a domain as the contract inference writes it in examples (order -> ORD-SYN-0042):
 * first letter, then the next consonants, completed with X Y Z (internal/idfmt.ExampleID).
 */
export function exampleIdOf(domain: string): string {
  if (!domain || domain === 'id') return 'OBJ-SYN-0042';
  const letters: string[] = [];
  for (const c of domain.toUpperCase()) {
    if (c < 'A' || c > 'Z') continue;
    if (!letters.length || !'AEIOU'.includes(c)) letters.push(c);
    if (letters.length === 3) break;
  }
  for (let i = 0; letters.length < 3; i++) letters.push('XYZ'[i % 3]);
  return `${letters.join('')}-SYN-0042`;
}

/** The message of a template error code (tk: the untyped translation). */
export function idFormatErrorText(code: IdFormatErrorCode | string, tk: (key: string, params?: Record<string, string | number>, fallback?: string) => string): string {
  return tk(`idf.err.${code}`, undefined, code);
}
