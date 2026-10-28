// Local state of the source: enrollment (certificate, CA chain, pinned keys), private key,
// signed policy cache, kill switch. Directory 0700, files 0600, atomic replace.

import { chmodSync, closeSync, constants, fstatSync, mkdirSync, openSync, readFileSync, renameSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

export function defaultStateDir(enrollUrl: string, serviceName: string): string {
  const id = createHash('sha256').update(enrollUrl + '\0' + serviceName).digest('hex').slice(0, 16);
  return join(homedir(), '.traffic-twin', id);
}

function statExists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

const POSIX = process.platform !== 'win32';
const myUid = typeof process.getuid === 'function' ? process.getuid() : -1;

export class StateStore {
  /** Called with the file name when a state file or the directory is not trusted (reported, never the content). */
  onUntrusted: ((what: string) => void) | undefined;

  constructor(readonly dir: string) {}

  /**
   * The directory must be ours. If it is ours but open to others (a pre-existing 0755
   * directory) it is tightened to 0700; anything else is refused. Files are checked one by one.
   */
  private dirTrusted(): boolean {
    if (!POSIX) return true;
    try {
      const st = statSync(this.dir);
      if (!st.isDirectory()) return false;
      if (myUid >= 0 && st.uid !== myUid) return false;
      if ((st.mode & 0o077) !== 0) {
        chmodSync(this.dir, 0o700);
        if ((statSync(this.dir).mode & 0o077) !== 0) return false;
      }
      return true;
    } catch {
      return false;
    }
  }

  private ensure(): void {
    mkdirSync(this.dir, { recursive: true, mode: 0o700 });
    if (!this.dirTrusted()) {
      this.onUntrusted?.('dir');
      throw new Error('state_dir_untrusted');
    }
  }

  readText(name: string): string | null {
    let fd = -1;
    try {
      if (!this.dirTrusted()) {
        if (statExists(this.dir)) this.onUntrusted?.('dir');
        return null;
      }
      // O_NOFOLLOW: a symlink planted in place of a state file is not followed; the checks
      // run on the opened descriptor, so they apply to the bytes that are then read.
      fd = openSync(join(this.dir, name), constants.O_RDONLY | (POSIX ? constants.O_NOFOLLOW : 0));
      const st = fstatSync(fd);
      if (POSIX && (!st.isFile() || (myUid >= 0 && st.uid !== myUid) || (st.mode & 0o077) !== 0)) {
        this.onUntrusted?.(name);
        return null;
      }
      return readFileSync(fd, 'utf8');
    } catch {
      return null;
    } finally {
      if (fd >= 0) closeSync(fd);
    }
  }

  readJson<T>(name: string): T | null {
    const t = this.readText(name);
    if (t === null) return null;
    try {
      return JSON.parse(t) as T;
    } catch {
      return null;
    }
  }

  writeText(name: string, text: string): void {
    this.ensure();
    const tmp = join(this.dir, '.' + name + '.' + process.pid + '.tmp');
    writeFileSync(tmp, text, { mode: 0o600 });
    chmodSync(tmp, 0o600);
    renameSync(tmp, join(this.dir, name));
  }

  writeJson(name: string, v: unknown): void {
    this.writeText(name, JSON.stringify(v));
  }

  remove(name: string): void {
    rmSync(join(this.dir, name), { force: true });
  }
}
