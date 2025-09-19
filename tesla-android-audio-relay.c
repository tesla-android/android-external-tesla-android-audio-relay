// tesla-android-audio-relay.c — PCM(f32) ingest -> FLAC/fMP4 mux -> WebSocket
// Low-latency tuned: ~5ms PCM pushes. Prepend cached INIT before next fragment for new clients.

#include <cutils/sockets.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>
#include <inttypes.h>
#include <signal.h>

#include "ws.h"
#include "ta_audio_mux.h"

// ===================== config =====================
#define AUDIO_SOCKET_PATH "/dev/socket/ws_audio"
#define WS_PORT 8080

// PCM format arriving from AudioFlinger/producer:
#define PCM_SAMPLE_RATE    48000
#define PCM_CHANNELS       2
#define PCM_BYTES_PER_SMP  4   // float32 interleaved
#define PCM_FRAME_BYTES    (PCM_CHANNELS * PCM_BYTES_PER_SMP)

// Server fragment target is set in muxer (~40ms)

// Extra chatty ingest logs
#define VERBOSE_INGEST 0

// ===================== logging ====================
#ifdef __ANDROID__
#include <android/log.h>
#define LOG_TAG "TA-RELAY"
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR,   LOG_TAG, __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN,    LOG_TAG, __VA_ARGS__)
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO,    LOG_TAG, __VA_ARGS__)
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,   LOG_TAG, __VA_ARGS__)
#else
#define LOGE(...) do { fprintf(stderr, "E/TA-RELAY: " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define LOGW(...) do { fprintf(stderr, "W/TA-RELAY: " __VA_ARGS__); fprintf(stderr, "\n"); } while(0)
#define LOGI(...) do { fprintf(stdout, "I/TA-RELAY: " __VA_ARGS__); fprintf(stdout, "\n"); } while(0)
#define LOGD(...) do { fprintf(stdout, "D/TA-RELAY: " __VA_ARGS__); fprintf(stdout, "\n"); } while(0)
#endif

static inline uint64_t mono_ms(void){
  struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ull + (uint64_t)ts.tv_nsec / 1000000ull;
}

// ===================== mux + ws ===================
static ta_mux_t* g_mux = NULL;

// WS state
static pthread_mutex_t g_ws_lock = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_ws_clients = 0;

// Cached init segment (ftyp+moov) for replay on connect
static uint8_t *g_init_buf = NULL;
static size_t   g_init_len = 0;

// “Send init before next fragment” toggle (broadcast once after a new client connects)
static volatile int g_need_init_before_next_fragment = 0;
static pthread_mutex_t g_init_lock = PTHREAD_MUTEX_INITIALIZER;

// Keep a little recent-stats
static volatile uint64_t g_frags_broadcast = 0;

static void cache_init_segment(const uint8_t* data, size_t len){
  pthread_mutex_lock(&g_ws_lock);
  free(g_init_buf);
  g_init_buf = (uint8_t*)malloc(len);
  if (g_init_buf) {
    memcpy(g_init_buf, data, len);
    g_init_len = len;
    LOGI("Cache: stored init segment %zu bytes", len);
  } else {
    g_init_len = 0;
    LOGE("Cache: OOM storing init!");
  }
  pthread_mutex_unlock(&g_ws_lock);
}

// Callbacks from muxer
static void cb_send_init(void* user, const uint8_t* data, size_t len) {
  (void)user;
  // Cache and broadcast immediately at startup (and any encoder reinit)
  cache_init_segment(data, len);

  pthread_mutex_lock(&g_ws_lock);
  ws_sendframe_bin(NULL, (const char*)data, (uint64_t)len);
  pthread_mutex_unlock(&g_ws_lock);
  LOGI("WS out (broadcast): INIT %zu bytes (clients=%d)", len, g_ws_clients);
}

static void cb_send_fragment(void* user, const uint8_t* data, size_t len) {
  (void)user;
  pthread_mutex_lock(&g_ws_lock);

  // If a client just connected, ensure they see INIT first (broadcast once).
  pthread_mutex_lock(&g_init_lock);
  int need = g_need_init_before_next_fragment;
  g_need_init_before_next_fragment = 0;
  pthread_mutex_unlock(&g_init_lock);

  if (need && g_init_buf && g_init_len) {
    ws_sendframe_bin(NULL, (const char*)g_init_buf, (uint64_t)g_init_len);
    LOGI("WS out (broadcast): INIT %zu bytes before fragment (clients=%d)", g_init_len, g_ws_clients);
  }

  ws_sendframe_bin(NULL, (const char*)data, (uint64_t)len);
  g_frags_broadcast++;

  pthread_mutex_unlock(&g_ws_lock);
  LOGD("WS out (broadcast): fragment %zu bytes (clients=%d total_frags=%" PRIu64 ")", len, g_ws_clients, g_frags_broadcast);
}

// ============ WS event handlers ============
void webSocketOnConnectionOpened(ws_cli_conn_t *client) {
  char *cli = ws_getaddress(client);
  pthread_mutex_lock(&g_ws_lock);
  g_ws_clients++;
  pthread_mutex_unlock(&g_ws_lock);

  // Mark that we need to broadcast INIT before the next fragment
  pthread_mutex_lock(&g_init_lock);
  g_need_init_before_next_fragment = 1;
  pthread_mutex_unlock(&g_init_lock);

  LOGI("WS client opened: %s (clients=%d) client=%p — will send INIT before next fragment",
       cli ? cli : "?", g_ws_clients, (void*)client);
}

void webSocketOnConnectionClosed(ws_cli_conn_t *client) {
  char *cli = ws_getaddress(client);
  pthread_mutex_lock(&g_ws_lock);
  if (g_ws_clients > 0) g_ws_clients--;
  pthread_mutex_unlock(&g_ws_lock);
  LOGI("WS client closed: %s (clients=%d) client=%p", cli ? cli : "?", g_ws_clients, (void*)client);
}

void webSocketOnMessage(__attribute__ ((unused)) ws_cli_conn_t *client,
       __attribute__ ((unused)) const unsigned char *msg, __attribute__ ((unused)) uint64_t size, __attribute__ ((unused)) int type) {}

// ===================== simple byte buffer =========
typedef struct {
  uint8_t* data;
  size_t   size;
  size_t   cap;
} bytebuf_t;

static void bb_init(bytebuf_t* b){ memset(b,0,sizeof(*b)); }
static void bb_append(bytebuf_t* b, const void* src, size_t n){
  if (b->size + n > b->cap){
    size_t newcap = b->cap ? b->cap : 4096;
    while (newcap < b->size + n) newcap *= 2;
    b->data = (uint8_t*)realloc(b->data, newcap);
    b->cap = newcap;
  }
  memcpy(b->data + b->size, src, n);
  b->size += n;
}
static size_t bb_consume(bytebuf_t* b, size_t n){
  if (n > b->size) n = b->size;
  if (n == b->size){ b->size = 0; return n; }
  memmove(b->data, b->data + n, b->size - n);
  b->size -= n; return n;
}

// ===================== PCM ingest -> mux ===========
static void feed_pcm_bytes_to_mux(const uint8_t* bytes, size_t len){
  static bytebuf_t s_accum; static int s_init = 0;
  if (!s_init){ bb_init(&s_accum); s_init = 1; }

#if VERBOSE_INGEST
  LOGD("INGEST: +%zu bytes pcm (accum=%zu)", len, s_accum.size);
#endif

  bb_append(&s_accum, bytes, len);

  const size_t full_bytes = (s_accum.size / PCM_FRAME_BYTES) * PCM_FRAME_BYTES;
  if (full_bytes == 0) {
#if VERBOSE_INGEST
    LOGD("INGEST: waiting for whole frame (need multiple of %d)", PCM_FRAME_BYTES);
#endif
    return;
  }

  const float* pcm = (const float*)s_accum.data;
  const int frames_total = (int)(full_bytes / PCM_FRAME_BYTES);

  // ~5 ms per push @ 48k
  const int max_frames_per_push = PCM_SAMPLE_RATE / 200; // 240 frames
  int pushed = 0;
  while (pushed < frames_total){
    int n = frames_total - pushed;
    if (n > max_frames_per_push) n = max_frames_per_push;

#if VERBOSE_INGEST
    LOGD("INGEST->MUX: push_f32 frames=%d (from offset=%d/%d)", n, pushed, frames_total);
#endif
    int r = ta_mux_push_pcm_f32(g_mux, pcm + (size_t)pushed * PCM_CHANNELS, n);
    if (r < 0) {
      LOGW("INGEST: ta_mux_push_pcm_f32 returned %d", r);
      break;
    }
    pushed += n;
  }

  bb_consume(&s_accum, (size_t)frames_total * PCM_FRAME_BYTES);
}

// ================ Relay thread (Unix domain socket) ================
static void* relayThread(void* arg) {
  (void)arg;

  int listen_fd = android_get_control_socket("ws_audio");
  if (listen_fd < 0) {
    LOGE("android_get_control_socket(ws_audio) failed");
    return NULL;
  }
  if (listen(listen_fd, 4) < 0) {
    LOGE("listen(ws_audio) failed");
    return NULL;
  }

  LOGI("PCM relay: waiting for incoming connections on %s", AUDIO_SOCKET_PATH);

  for (;;) {
    int client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) continue;

    LOGI("PCM relay: client connected (fd=%d)", client_fd);

    uint64_t t0 = mono_ms();
    uint64_t last_report = t0;
    uint64_t bytes_in = 0;
    uint64_t frames_in = 0;
    uint64_t msgs = 0;

    for (;;) {
      uint32_t len_be;
      ssize_t r = recv(client_fd, &len_be, sizeof(len_be), MSG_WAITALL);
      if (r <= 0) {
        LOGI("PCM relay: client closed (fd=%d), r=%zd", client_fd, r);
        break;
      }

      uint32_t len = ntohl(len_be);
      msgs++;

      if (len == 0) {
        LOGW("PCM relay: got zero-length message (%" PRIu64 ")", msgs);
        continue;
      }

      if (len % PCM_FRAME_BYTES != 0) {
        LOGW("PCM relay: non-frame-aligned payload: %u bytes (frameBytes=%d)", len, PCM_FRAME_BYTES);
      }

      char* buf = (char*)malloc(len);
      if (!buf) {
        LOGE("PCM relay: OOM for %u bytes; dropping", len);
        char tmp[4096];
        size_t left = len;
        while (left > 0) {
          ssize_t g = recv(client_fd, tmp, left > sizeof(tmp)? sizeof(tmp) : left, MSG_WAITALL);
          if (g <= 0) break;
          left -= (size_t)g;
        }
        continue;
      }

      ssize_t got = recv(client_fd, buf, len, MSG_WAITALL);
      if (got != (ssize_t)len) {
        LOGW("PCM relay: short read body: got=%zd exp=%u", got, len);
        free(buf);
        break;
      }

      bytes_in += (uint64_t)len;
      frames_in += (uint64_t)(len / PCM_FRAME_BYTES);

#if VERBOSE_INGEST
      const int frames_msg = (int)(len / PCM_FRAME_BYTES);
      LOGD("PCM relay: msg#%" PRIu64 " len=%u bytes (~%d frames @%dch/%dB) q_ingest",
           msgs, len, frames_msg, PCM_CHANNELS, PCM_BYTES_PER_SMP);
#endif

      feed_pcm_bytes_to_mux((const uint8_t*)buf, (size_t)len);
      free(buf);

      uint64_t now = mono_ms();
      if (now - last_report >= 1000) {
        double secs = (now - t0) / 1000.0;
        double brate = bytes_in / (secs ? secs : 1.0);
        double frate = frames_in / (secs ? secs : 1.0);
        LOGI("PCM relay stats: msgs=%" PRIu64 " bytes=%" PRIu64 " (%.0f B/s) frames=%" PRIu64 " (%.0f fps) frags_bcast=%" PRIu64,
             msgs, bytes_in, brate, frames_in, frate, g_frags_broadcast);
        last_report = now;
      }
    }

    close(client_fd);
  }

  close(listen_fd);
  unlink(AUDIO_SOCKET_PATH);
  return NULL;
}

// Simple ping to keep WS alive
static void *pingThread(__attribute__ ((unused)) void *arg) {
  while(1) {
    sleep(1);
    ws_ping(NULL, 5);
  }
  return NULL;
}

int main(void)
{
  // Prevent SIGPIPE from killing the process on socket errors
  signal(SIGPIPE, SIG_IGN);

  // Create muxer with WS broadcast callbacks
  ta_mux_callbacks_t cbs = {
    .send_init = cb_send_init,
    .send_fragment = cb_send_fragment,
    .user = NULL
  };

  // FRAG_MS is enforced to ~40ms in muxer; argument value here is ignored there.
  g_mux = ta_mux_create_flac(PCM_SAMPLE_RATE, PCM_CHANNELS, /*frag_ms*/ 40, &cbs);
  if (!g_mux) {
    LOGE("Failed to create FLAC fMP4 muxer");
    return 1;
  }

  pthread_t ping_thread;
  pthread_create(&ping_thread, NULL, pingThread, NULL);

  pthread_t relay_thread;
  pthread_create(&relay_thread, NULL, relayThread, NULL);

  struct ws_events evs;
  evs.onopen    = &webSocketOnConnectionOpened;
  evs.onclose   = &webSocketOnConnectionClosed;
  evs.onmessage = &webSocketOnMessage;

  LOGI("WebSocket: starting on port %d ...", WS_PORT);
  ws_socket(&evs, WS_PORT, 0, 1000);

  pthread_join(ping_thread, NULL);
  pthread_join(relay_thread, NULL);

  ta_mux_close(g_mux);

  // free cached init on shutdown
  pthread_mutex_lock(&g_ws_lock);
  free(g_init_buf); g_init_buf = NULL; g_init_len = 0;
  pthread_mutex_unlock(&g_ws_lock);

  return 0;
}
