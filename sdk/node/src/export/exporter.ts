// OTLP/HTTP JSON exporter (event.md 4): bounded queue, batches of at most 512 events or
// 4 MiB, retry with exponential backoff and jitter on 429/502/503/504 and network errors
// (at most 5 times, Retry-After honoured), drop-oldest under pressure. The app never waits.

import type https from 'node:https';
import { otlpBody, type QueuedEvent, type Resource } from './event.js';
import { request, type HttpResult } from '../fleet/http.js';
import { debug } from '../log.js';

export interface ExportCounters {
  events_sent: number;
  events_dropped_queue: number;
  events_rejected: number;
  send_errors: number;
}

export interface ExporterOptions {
  url: string;
  agent: https.Agent;
  resource: Resource;
  counters: ExportCounters;
  onError: (code: string) => void;
  maxEvents?: number;
  maxBytes?: number;
  batchEvents?: number;
  batchBytes?: number;
  flushMs?: number;
  maxRetries?: number;
  baseBackoffMs?: number;
  maxBackoffMs?: number;
}

const sizeOf = (e: QueuedEvent): number => e.size ?? e.json.length;

const RETRYABLE = new Set([429, 502, 503, 504]);
const DROP = new Set([400, 401, 403, 413]);

export class Exporter {
  private queue: QueuedEvent[] = [];
  private head = 0;
  private bytes = 0;
  private inFlight = false;
  private timer: NodeJS.Timeout | undefined;
  private retryTimer: NodeJS.Timeout | undefined;
  private stopped = false;
  /** Bumped by clear() (kill switch, revocation): a batch built under an older generation is never sent. */
  private gen = 0;
  private readonly o: Required<Omit<ExporterOptions, 'url' | 'agent' | 'resource' | 'counters' | 'onError'>> & ExporterOptions;

  constructor(opts: ExporterOptions) {
    this.o = {
      maxEvents: 10_000,
      maxBytes: 16 << 20,
      batchEvents: 512,
      batchBytes: 4 << 20,
      flushMs: 1000,
      maxRetries: 5,
      baseBackoffMs: 1000,
      maxBackoffMs: 30_000,
      ...opts,
    };
    this.timer = setInterval(() => this.kick(), this.o.flushMs);
    this.timer.unref();
  }

  get size(): { events: number; bytes: number } {
    return { events: this.queue.length - this.head, bytes: this.bytes };
  }

  setTarget(url: string, agent: https.Agent): void {
    this.o.url = url;
    this.o.agent = agent;
  }

  enqueue(e: QueuedEvent): void {
    if (this.stopped) return;
    this.queue.push(e);
    this.bytes += sizeOf(e);
    while (this.queue.length - this.head > this.o.maxEvents || this.bytes > this.o.maxBytes) {
      const old = this.queue[this.head++]!;
      this.bytes -= sizeOf(old);
      this.o.counters.events_dropped_queue++;
    }
    if (this.head > 4096 && this.head * 2 > this.queue.length) {
      this.queue = this.queue.slice(this.head);
      this.head = 0;
    }
    if (this.queue.length - this.head >= this.o.batchEvents) setImmediate(() => this.kick());
  }

  /** Drops everything queued (kill switch). */
  clear(): void {
    this.gen++;
    this.o.counters.events_dropped_queue += this.queue.length - this.head;
    this.queue = [];
    this.head = 0;
    this.bytes = 0;
  }

  stop(): void {
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    if (this.retryTimer) clearTimeout(this.retryTimer);
  }

  /** Sends what is queued; resolves when the queue is empty or a send failed. */
  async flush(): Promise<void> {
    for (let i = 0; i < 1000 && this.queue.length - this.head > 0 && !this.stopped; i++) {
      if (this.inFlight) {
        await new Promise((r) => setTimeout(r, 20));
        continue;
      }
      const ok = await this.sendOne(false);
      if (!ok) return;
    }
  }

  private kick(): void {
    if (this.inFlight || this.stopped || this.retryTimer || this.queue.length - this.head === 0) return;
    void this.sendOne(true);
  }

  private takeBatch(): QueuedEvent[] {
    const batch: QueuedEvent[] = [];
    let size = 0;
    while (this.head < this.queue.length && batch.length < this.o.batchEvents) {
      const e = this.queue[this.head]!;
      const sz = sizeOf(e);
      if (batch.length > 0 && size + sz > this.o.batchBytes) break;
      batch.push(e);
      size += sz;
      this.head++;
      this.bytes -= sz;
    }
    return batch;
  }

  private async sendOne(retryLater: boolean): Promise<boolean> {
    this.inFlight = true;
    const batch = this.takeBatch();
    const gen = this.gen;
    try {
      for (let attempt = 0; ; attempt++) {
        // Kill switch or revocation while this batch was held (first attempt or between
        // retries, Retry-After included): it is dropped, never sent.
        if (gen !== this.gen) {
          this.o.counters.events_dropped_queue += batch.length;
          return false;
        }
        let res: HttpResult | undefined;
        let netErr = false;
        try {
          res = await request({
            method: 'POST',
            url: this.o.url,
            agent: this.o.agent,
            headers: { 'content-type': 'application/json' },
            body: otlpBody(batch, this.o.resource, Date.now()),
            timeoutMs: 15_000,
            maxResponseBytes: 64 << 10,
          });
        } catch {
          netErr = true;
        }
        if (res && res.status >= 200 && res.status < 300) {
          let rejected = 0;
          try {
            const j = JSON.parse(res.body.toString('utf8') || '{}') as { partialSuccess?: { rejectedLogRecords?: number | string } };
            rejected = Number(j.partialSuccess?.rejectedLogRecords ?? 0) || 0;
          } catch {
            rejected = 0;
          }
          rejected = Math.min(Math.max(0, rejected), batch.length);
          this.o.counters.events_sent += batch.length - rejected;
          this.o.counters.events_rejected += rejected;
          if (rejected) this.o.onError('intake_partial_reject');
          return true;
        }
        const retryable = netErr || (res !== undefined && RETRYABLE.has(res.status));
        if (!retryable || attempt >= this.o.maxRetries || this.stopped) {
          if (res && DROP.has(res.status)) this.o.counters.events_rejected += batch.length;
          else this.o.counters.events_dropped_queue += batch.length;
          this.o.counters.send_errors++;
          this.o.onError(res ? 'intake_http_' + res.status : 'intake_network');
          debug('export_drop', res ? res.status : 'network');
          return false;
        }
        this.o.counters.send_errors++;
        let delay = Math.min(this.o.maxBackoffMs, this.o.baseBackoffMs * 2 ** attempt);
        delay = delay / 2 + Math.random() * (delay / 2);
        const ra = res?.headers['retry-after'];
        if (typeof ra === 'string') {
          const secs = /^[0-9]+$/.test(ra.trim()) ? Number(ra) * 1000 : Date.parse(ra) - Date.now();
          if (Number.isFinite(secs) && secs > 0) delay = Math.min(Math.max(delay, secs), 300_000);
        }
        await new Promise<void>((r) => {
          this.retryTimer = setTimeout(() => {
            this.retryTimer = undefined;
            r();
          }, delay);
          this.retryTimer.unref();
        });
        if (this.stopped) return false;
        void retryLater;
        // (the generation is checked again at the top of the loop)
      }
    } finally {
      this.inFlight = false;
    }
  }
}
