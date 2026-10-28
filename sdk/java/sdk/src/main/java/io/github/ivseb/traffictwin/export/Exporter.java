package io.github.ivseb.traffictwin.export;

import io.github.ivseb.traffictwin.export.EventBuilder.Queued;
import io.github.ivseb.traffictwin.fleet.FleetClient;
import io.github.ivseb.traffictwin.fleet.FleetClient.Response;
import io.github.ivseb.traffictwin.sanitizer.Json;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.ScheduledThreadPoolExecutor;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.Consumer;
import java.util.zip.GZIPOutputStream;

/**
 * OTLP/HTTP JSON exporter (event.md 4): bounded queue, batches of at most 512 events or 4 MiB,
 * retry with exponential backoff and jitter on 429/502/503/504 and network errors (at most 5
 * times, Retry-After honoured), drop-oldest under pressure. The application never waits for it.
 */
public final class Exporter {
    /** Counters shared with the heartbeat. */
    public static final class Counters {
        public final AtomicLong exchangesSeen = new AtomicLong();
        public final AtomicLong exchangesSampled = new AtomicLong();
        public final AtomicLong eventsSent = new AtomicLong();
        public final AtomicLong eventsDroppedQueue = new AtomicLong();
        public final AtomicLong eventsRejected = new AtomicLong();
        public final AtomicLong sendErrors = new AtomicLong();
        public final AtomicLong sanitizerErrors = new AtomicLong();
    }

    private static final int BATCH_EVENTS = 512;
    private static final int BATCH_BYTES = 4 << 20;

    private final Object lock = new Object();
    private final ArrayDeque<Queued> queue = new ArrayDeque<>();
    private long bytes = 0;
    private volatile boolean stopped = false;
    private volatile HttpClient http;
    private volatile URI url;
    private final String serviceName;
    private final String sourceId;
    private final Counters counters;
    private final Consumer<String> onError;
    private final int maxEvents;
    private final long maxBytes;
    private final int maxRetries;
    private final long baseBackoffMs;
    private final long maxBackoffMs;
    private final boolean gzip;
    private final ScheduledExecutorService scheduler;
    private boolean inFlight = false;

    public Exporter(HttpClient http, URI url, String serviceName, String sourceId, Counters counters, Consumer<String> onError, long flushMs) {
        this(http, url, serviceName, sourceId, counters, onError, flushMs, 10_000, 16L << 20, 5, 1000, 30_000, false);
    }

    public Exporter(HttpClient http, URI url, String serviceName, String sourceId, Counters counters, Consumer<String> onError, long flushMs,
                    int maxEvents, long maxBytes, int maxRetries, long baseBackoffMs, long maxBackoffMs, boolean gzip) {
        this.http = http;
        this.url = url;
        this.serviceName = serviceName;
        this.sourceId = sourceId;
        this.counters = counters;
        this.onError = onError;
        this.maxEvents = maxEvents;
        this.maxBytes = maxBytes;
        this.maxRetries = maxRetries;
        this.baseBackoffMs = baseBackoffMs;
        this.maxBackoffMs = maxBackoffMs;
        this.gzip = gzip;
        ScheduledThreadPoolExecutor s = new ScheduledThreadPoolExecutor(1, r -> {
            Thread t = new Thread(r, "tt-export");
            t.setDaemon(true);
            return t;
        });
        s.setRemoveOnCancelPolicy(true);
        this.scheduler = s;
        s.scheduleWithFixedDelay(this::kick, flushMs, flushMs, TimeUnit.MILLISECONDS);
    }

    public void setTarget(URI url, HttpClient http) {
        this.url = url;
        this.http = http;
    }

    public int size() {
        synchronized (lock) {
            return queue.size();
        }
    }

    public long sizeBytes() {
        synchronized (lock) {
            return bytes;
        }
    }

    /** Kill-switch generation: {@link #clear()} bumps it; a batch taken under an older one is dropped, never (re)sent. */
    public long generation() {
        synchronized (lock) {
            return gen;
        }
    }

    private long gen;

    public void enqueue(Queued e) {
        enqueue(e, -1);
    }

    /** {@code atGen} is the generation read before the event was built (-1: unconditional). */
    public void enqueue(Queued e, long atGen) {
        if (stopped) return;
        boolean full;
        synchronized (lock) {
            if (atGen >= 0 && atGen != gen) {
                counters.eventsDroppedQueue.incrementAndGet();
                return;
            }
            queue.addLast(e);
            bytes += e.json().length();
            while (queue.size() > maxEvents || bytes > maxBytes) {
                Queued old = queue.pollFirst();
                bytes -= old.json().length();
                counters.eventsDroppedQueue.incrementAndGet();
            }
            full = queue.size() >= BATCH_EVENTS;
        }
        if (full) scheduler.execute(this::kick);
    }

    /** Drops everything queued (kill switch). */
    public void clear() {
        synchronized (lock) {
            gen++;
            counters.eventsDroppedQueue.addAndGet(queue.size());
            queue.clear();
            bytes = 0;
        }
    }

    public void stop() {
        stopped = true;
        scheduler.shutdownNow();
    }

    /** Sends what is queued; returns when the queue is empty or a send failed. */
    public void flush() {
        for (int i = 0; i < 1000 && !stopped; i++) {
            synchronized (lock) {
                if (queue.isEmpty()) return;
                if (inFlight) {
                    try {
                        lock.wait(20);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    }
                    continue;
                }
            }
            if (!sendOne()) return;
        }
    }

    private void kick() {
        synchronized (lock) {
            if (inFlight || stopped || queue.isEmpty()) return;
        }
        while (!stopped && sendOne()) {
            synchronized (lock) {
                if (queue.isEmpty()) return;
            }
        }
    }

    private List<Queued> takeBatch() {
        List<Queued> batch = new ArrayList<>();
        long size = 0;
        synchronized (lock) {
            batchGen = gen;
            while (!queue.isEmpty() && batch.size() < BATCH_EVENTS) {
                Queued e = queue.peekFirst();
                if (!batch.isEmpty() && size + e.json().length() > BATCH_BYTES) break;
                queue.pollFirst();
                batch.add(e);
                size += e.json().length();
                bytes -= e.json().length();
            }
        }
        return batch;
    }

    /** One batch with retries. False when it was dropped or nothing was sent. */
    private long batchGen;

    private boolean stale(List<Queued> batch, long g) {
        synchronized (lock) {
            if (g == gen) return false;
        }
        counters.eventsDroppedQueue.addAndGet(batch.size());
        return true;
    }

    private boolean sendOne() {
        List<Queued> batch;
        synchronized (lock) {
            if (inFlight) return false;
            inFlight = true;
        }
        try {
            batch = takeBatch();
            if (batch.isEmpty()) return false;
            final long g = batchGen;
            for (int attempt = 0;; attempt++) {
                if (stale(batch, g)) return false; // the kill switch arrived: never (re)send
                Response res = null;
                boolean netErr = false;
                try {
                    byte[] body = EventBuilder.otlpBody(batch, serviceName, sourceId, System.currentTimeMillis()).getBytes(StandardCharsets.UTF_8);
                    Map<String, String> headers = new java.util.LinkedHashMap<>();
                    headers.put("content-type", "application/json");
                    if (gzip) {
                        headers.put("content-encoding", "gzip");
                        body = gzipBytes(body);
                    }
                    res = FleetClient.send(http, "POST", url, headers, body, Duration.ofSeconds(15), 64 << 10);
                } catch (IOException e) {
                    netErr = true;
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    counters.eventsDroppedQueue.addAndGet(batch.size());
                    return false;
                }
                if (res != null && res.status() >= 200 && res.status() < 300) {
                    long rejected = 0;
                    Object j = res.json();
                    if (j instanceof Map<?, ?> m && m.get("partialSuccess") instanceof Map<?, ?> ps) {
                        Object r = ps.get("rejectedLogRecords");
                        try {
                            if (r instanceof Json.Lex l) rejected = (long) Double.parseDouble(l.lex);
                            else if (r instanceof String s) rejected = Long.parseLong(s);
                        } catch (NumberFormatException e) {
                            rejected = 0;
                        }
                    }
                    rejected = Math.min(Math.max(0, rejected), batch.size());
                    counters.eventsSent.addAndGet(batch.size() - rejected);
                    counters.eventsRejected.addAndGet(rejected);
                    if (rejected > 0) onError.accept("intake_partial_reject");
                    return true;
                }
                int st = res == null ? -1 : res.status();
                boolean retryable = netErr || st == 429 || st == 502 || st == 503 || st == 504;
                if (!retryable || attempt >= maxRetries || stopped) {
                    if (st == 400 || st == 401 || st == 403 || st == 413) counters.eventsRejected.addAndGet(batch.size());
                    else counters.eventsDroppedQueue.addAndGet(batch.size());
                    counters.sendErrors.incrementAndGet();
                    onError.accept(res != null ? "intake_http_" + st : "intake_network");
                    return false;
                }
                counters.sendErrors.incrementAndGet();
                double delay = Math.min(maxBackoffMs, baseBackoffMs * Math.pow(2, attempt));
                delay = delay / 2 + ThreadLocalRandom.current().nextDouble() * (delay / 2);
                String ra = res == null ? null : res.header("retry-after");
                if (ra != null) {
                    double ms = retryAfterMs(ra.trim());
                    if (ms > 0) delay = Math.min(Math.max(delay, ms), 300_000);
                }
                try {
                    Thread.sleep((long) delay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    counters.eventsDroppedQueue.addAndGet(batch.size());
                    return false;
                }
                if (stopped) {
                    counters.eventsDroppedQueue.addAndGet(batch.size());
                    return false;
                }
            }
        } finally {
            synchronized (lock) {
                inFlight = false;
                lock.notifyAll();
            }
        }
    }

    private static double retryAfterMs(String v) {
        try {
            if (v.matches("[0-9]+")) return Double.parseDouble(v) * 1000;
            return ZonedDateTime.parse(v, java.time.format.DateTimeFormatter.RFC_1123_DATE_TIME).toInstant().toEpochMilli() - System.currentTimeMillis();
        } catch (RuntimeException e) {
            return 0;
        }
    }

    private static byte[] gzipBytes(byte[] in) throws IOException {
        ByteArrayOutputStream bo = new ByteArrayOutputStream(in.length / 4 + 64);
        try (GZIPOutputStream g = new GZIPOutputStream(bo)) {
            g.write(in);
        }
        return bo.toByteArray();
    }
}
