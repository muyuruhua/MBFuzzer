/*
 * gcov_flush_daemon.c — LD_PRELOAD library for periodic gcov data flushing.
 *
 * PURPOSE:
 *   When a gcov-instrumented process (e.g. mosquitto) crashes (SIGSEGV,
 *   SIGABRT, etc.), the atexit() handler that normally writes .gcda files
 *   is never called, and ALL coverage data is lost.
 *
 *   This library spawns a background thread that calls __gcov_flush()
 *   every GCOV_FLUSH_INTERVAL seconds (default: 30).  This ensures that
 *   even if the process crashes, the .gcda files contain coverage data
 *   up to the last flush point.
 *
 * USAGE:
 *   LD_PRELOAD=/usr/local/lib/gcov_flush_daemon.so \
 *     /opt/mosquitto-gcov/src/mosquitto -c /opt/mosquitto.conf
 *
 * ENVIRONMENT:
 *   GCOV_FLUSH_INTERVAL  — flush interval in seconds (default: 30)
 *
 * COMPATIBILITY:
 *   GCC  < 11: uses __gcov_flush()  (writes + resets counters)
 *   GCC >= 11: uses __gcov_dump()   (writes without reset)
 *   Detected at compile time via __GNUC__ version macros.
 *
 * OCP NOTE:
 *   This is a NEW extension file.  No original MBFuzzer or mosquitto
 *   source files are modified.
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

/* ── gcov API selection ─────────────────────────────────────────────── */
/*
 * CRITICAL: Use __attribute__((weak)) so the symbol resolves to NULL in
 * non-gcov-instrumented binaries (e.g. 'date', 'pgrep').  Without weak
 * linkage, calling __gcov_flush() in a non-instrumented process crashes it.
 * LD_PRELOAD affects ALL processes in the container, not just mosquitto.
 */
#if defined(__GNUC__) && (__GNUC__ > 11 || (__GNUC__ == 11 && __GNUC_MINOR__ >= 1))
  /* GCC >= 11.1: __gcov_dump() writes .gcda without resetting counters */
  extern void __gcov_dump(void) __attribute__((weak));
  #define GCOV_SAVE() do { if (__gcov_dump) __gcov_dump(); } while (0)
  #define GCOV_METHOD "dump"
  #define GCOV_AVAILABLE() (!!__gcov_dump)
#else
  /* GCC < 11 (e.g. 9.4 on Ubuntu 20.04):
     __gcov_flush() writes .gcda AND resets counters to zero.
     This is acceptable — next flush will capture new incremental data,
     and gcovr merges .gcda files so the union is correct. */
  extern void __gcov_flush(void) __attribute__((weak));
  #define GCOV_SAVE() do { if (__gcov_flush) __gcov_flush(); } while (0)
  #define GCOV_METHOD "flush"
  #define GCOV_AVAILABLE() (!!__gcov_flush)
#endif

/* ── Default interval ───────────────────────────────────────────────── */
#define DEFAULT_FLUSH_INTERVAL 30

static int flush_interval = DEFAULT_FLUSH_INTERVAL;
static volatile sig_atomic_t keep_running = 1;

/* ── Signal handler: also flush on fatal signals before dying ──────── */
static void crash_handler(int sig) {
    /* Best-effort flush on crash — may be partially written, but better
       than losing everything. */
    GCOV_SAVE();
    /* Re-raise with default handler to get proper core dump / exit code */
    signal(sig, SIG_DFL);
    raise(sig);
}

/* ── Background thread ─────────────────────────────────────────────── */
static void *flush_thread(void *arg) {
    (void)arg;
    while (keep_running) {
        sleep((unsigned)flush_interval);
        if (keep_running) {
            GCOV_SAVE();
        }
    }
    return NULL;
}

/* ── Constructor: runs when the shared library is loaded ────────────── */
__attribute__((constructor))
static void gcov_flush_daemon_init(void) {
    /* Skip initialization for non-gcov-instrumented binaries.
       LD_PRELOAD loads this into every process (date, pgrep, sh, etc.)
       but only the gcov-instrumented mosquitto needs the flush daemon. */
    if (!GCOV_AVAILABLE()) {
        return;
    }

    /* Read interval from environment */
    const char *env_val = getenv("GCOV_FLUSH_INTERVAL");
    if (env_val) {
        int v = atoi(env_val);
        if (v > 0) {
            flush_interval = v;
        }
    }

    fprintf(stderr,
            "[gcov_flush_daemon] Periodic gcov %s every %ds (PID=%d)\n",
            GCOV_METHOD, flush_interval, (int)getpid());

    /* Install crash signal handlers */
    signal(SIGSEGV, crash_handler);
    signal(SIGABRT, crash_handler);
    signal(SIGBUS,  crash_handler);
    signal(SIGFPE,  crash_handler);
    signal(SIGILL,  crash_handler);

    /* Spawn background flush thread */
    pthread_t tid;
    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    if (pthread_create(&tid, &attr, flush_thread, NULL) != 0) {
        perror("[gcov_flush_daemon] pthread_create failed");
    }
    pthread_attr_destroy(&attr);
}

/* ── Destructor: final flush on normal exit ─────────────────────────── */
__attribute__((destructor))
static void gcov_flush_daemon_fini(void) {
    if (!GCOV_AVAILABLE()) {
        return;
    }
    keep_running = 0;
    GCOV_SAVE();
    fprintf(stderr, "[gcov_flush_daemon] Final gcov %s on exit (PID=%d)\n",
            GCOV_METHOD, (int)getpid());
}
