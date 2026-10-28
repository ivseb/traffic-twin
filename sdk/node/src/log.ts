// Diagnostic log. Only error codes and counts are ever written, never payload values
// (threat model M14). Off unless TT_DEBUG is set.

let enabled = /^(1|true|yes|debug)$/i.test(process.env.TT_DEBUG ?? '');

export function setDebug(on: boolean): void {
  enabled = on;
}

export function debug(code: string, detail?: string | number): void {
  if (!enabled) return;
  try {
    process.stderr.write('[traffic-twin] ' + code + (detail !== undefined ? ' ' + String(detail) : '') + '\n');
  } catch {
    // ignore
  }
}

/** A line that is always written (configuration problems that stop the capture). Codes and fixed text only. */
export function warn(text: string): void {
  try {
    process.stderr.write('[traffic-twin] ' + text + '\n');
  } catch {
    // ignore
  }
}
