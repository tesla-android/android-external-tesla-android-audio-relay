// ta_audio_mux.c — FLAC→fMP4 muxer with robust fragment splitter and low-latency tuning.
// Logging is runtime-configurable on Android via system properties:
//
//   persist.ta.mux.level           (0=ERROR,1=WARN,2=INFO,3=DEBUG; default 2)
//   persist.ta.mux.trace.splitter  (0/1; default 0)  - detailed box parsing
//   persist.ta.mux.trace.avio      (0/1; default 0)  - avio write + hexdump
//   persist.ta.mux.trace.push      (0/1; default 0)  - FIFO/push pacing
//
// Non-Android builds fall back to compile-time defaults below.

#include "ta_audio_mux.h"

#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavutil/opt.h>
#include <libavutil/samplefmt.h>
#include <libavutil/channel_layout.h>
#include <libswresample/swresample.h>

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

// ===== runtime-configurable logging =====
#ifndef TA_MUX_LOG_LEVEL_DEFAULT
#define TA_MUX_LOG_LEVEL_DEFAULT 2   // INFO
#endif
#ifndef TA_MUX_TRACE_SPLITTER_DEFAULT
#define TA_MUX_TRACE_SPLITTER_DEFAULT 0
#endif
#ifndef TA_MUX_TRACE_AVIO_DEFAULT
#define TA_MUX_TRACE_AVIO_DEFAULT 0
#endif
#ifndef TA_MUX_TRACE_PUSH_DEFAULT
#define TA_MUX_TRACE_PUSH_DEFAULT 0
#endif

static int g_log_level = TA_MUX_LOG_LEVEL_DEFAULT;         // 0..3
static int g_trace_splitter = TA_MUX_TRACE_SPLITTER_DEFAULT;
static int g_trace_avio     = TA_MUX_TRACE_AVIO_DEFAULT;
static int g_trace_push     = TA_MUX_TRACE_PUSH_DEFAULT;

#ifdef __ANDROID__
#include <android/log.h>
#include <sys/system_properties.h>
#define LOG_TAG "TA-MUX"
#define _ALOG(prio, fmt, ...) __android_log_print(prio, LOG_TAG, fmt, ##__VA_ARGS__)
#else
#include <stdio.h>
#define ANDROID_LOG_ERROR 0
#define ANDROID_LOG_WARN  1
#define ANDROID_LOG_INFO  2
#define ANDROID_LOG_DEBUG 3
#define _ALOG(prio, fmt, ...) \
  do { FILE* _f = (prio==ANDROID_LOG_ERROR)?stderr:stdout; \
       const char* p = (prio==ANDROID_LOG_ERROR)?"E":(prio==ANDROID_LOG_WARN)?"W":(prio==ANDROID_LOG_INFO)?"I":"D"; \
       fprintf(_f, "%s/TA-MUX: " fmt "\n", p, ##__VA_ARGS__); } while(0)
#endif

#define LOGE(...) do { if (g_log_level >= 0) _ALOG(ANDROID_LOG_ERROR, __VA_ARGS__); } while(0)
#define LOGW(...) do { if (g_log_level >= 1) _ALOG(ANDROID_LOG_WARN,  __VA_ARGS__); } while(0)
#define LOGI(...) do { if (g_log_level >= 2) _ALOG(ANDROID_LOG_INFO,  __VA_ARGS__); } while(0)
#define LOGD(...) do { if (g_log_level >= 3) _ALOG(ANDROID_LOG_DEBUG, __VA_ARGS__); } while(0)

#define TR_SPLIT(...) do { if (g_trace_splitter) LOGD(__VA_ARGS__); } while(0)
#define TR_AVIO(...)  do { if (g_trace_avio)     LOGD(__VA_ARGS__); } while(0)
#define TR_PUSH(...)  do { if (g_trace_push)     LOGD(__VA_ARGS__); } while(0)

#ifdef __ANDROID__
static int read_sysprop_int(const char* key, int defv){
  char buf[PROP_VALUE_MAX] = {0};
  int n = __system_property_get(key, buf);
  if (n <= 0) return defv;
  int v = defv;
  if (sscanf(buf, "%d", &v) == 1) return v;
  return defv;
}
static void init_runtime_logging(void){
  g_log_level     = read_sysprop_int("persist.ta.mux.level",          TA_MUX_LOG_LEVEL_DEFAULT);
  g_trace_splitter= read_sysprop_int("persist.ta.mux.trace.splitter", TA_MUX_TRACE_SPLITTER_DEFAULT);
  g_trace_avio    = read_sysprop_int("persist.ta.mux.trace.avio",     TA_MUX_TRACE_AVIO_DEFAULT);
  g_trace_push    = read_sysprop_int("persist.ta.mux.trace.push",     TA_MUX_TRACE_PUSH_DEFAULT);

  // clamp
  if (g_log_level < 0) g_log_level = 0;
  if (g_log_level > 3) g_log_level = 3;
  g_trace_splitter = !!g_trace_splitter;
  g_trace_avio     = !!g_trace_avio;
  g_trace_push     = !!g_trace_push;

  LOGI("log config: level=%d trace{splitter=%d, avio=%d, push=%d}",
       g_log_level, g_trace_splitter, g_trace_avio, g_trace_push);
}
#else
static void init_runtime_logging(void){
  // Non-Android: keep compile-time defaults
  LOGI("log config (static): level=%d trace{splitter=%d, avio=%d, push=%d}",
       g_log_level, g_trace_splitter, g_trace_avio, g_trace_push);
}
#endif

#ifndef AV_CHANNEL_LAYOUT_STEREO
#define AV_CHANNEL_LAYOUT_STEREO (AV_CH_LAYOUT_STEREO)
#endif

// ------------ utils ------------
static const char* errstr(int e, char buf[AV_ERROR_MAX_STRING_SIZE]){
  return av_make_error_string(buf, AV_ERROR_MAX_STRING_SIZE, e);
}
static inline uint32_t be32(const uint8_t *p){ return (p[0]<<24)|(p[1]<<16)|(p[2]<<8)|p[3]; }
static inline uint32_t tagu(const char *t){ return ((uint32_t)t[0]<<24)|((uint32_t)t[1]<<16)|((uint32_t)t[2]<<8)|((uint32_t)t[3]); }

// tiny hexdump for avio head
static void hexdump16(const uint8_t* p, int n){
  if (!g_trace_avio && g_log_level < 3) return; // compile-time cheap guard
  int m = n < 16 ? n : 16;
  char buf[3*16+1]; char *w = buf;
  for (int i=0;i<m;i++) w += sprintf(w, "%02X", p[i]);
  *w = 0;
  LOGD("avio head: %s", buf);
}

// ---- safe opt setters (never fatal, always log) ----
static void opt_set_str(void *ctx, const char *key, const char *val) {
  int r = av_opt_set(ctx, key, val, 0);
  if (r < 0) {
    char e[AV_ERROR_MAX_STRING_SIZE]; av_strerror(r, e, sizeof e);
    LOGW("opt_set_str: %s=%s not applied (%s)", key, val, e);
  } else {
    LOGI("opt_set_str: %s=%s", key, val);
  }
}
static void opt_set_int(void *ctx, const char *key, int64_t v) {
  int r = av_opt_set_int(ctx, key, v, 0);
  if (r < 0) {
    char e[AV_ERROR_MAX_STRING_SIZE]; av_strerror(r, e, sizeof e);
    LOGW("opt_set_int: %s=%" PRId64 " not applied (%s)", key, v, e);
  } else {
    LOGI("opt_set_int: %s=%" PRId64, key, v);
  }
}

// ------------ movflags ------------
static void try_set_movflags(void *ctx) {
  // No '+dash' to avoid per-fragment sidx; keep default_base_moof.
  const char *variants[] = {
    "empty_moov+separate_moof+default_base_moof+frag_discont",
    "empty_moov+separate_moof+default_base_moof",
    "empty_moov+separate_moof",
    NULL
  };
  for (int i = 0; variants[i]; i++) {
    int r = av_opt_set(ctx, "movflags", variants[i], 0);
    if (r == 0) { LOGI("movflags applied: %s", variants[i]); return; }
    LOGW("movflags unsupported: %s (err=%d)", variants[i], r);
  }
  LOGW("movflags not set; continuing");
}

// ---------- fMP4 splitter ----------
typedef enum { PHASE_INIT, PHASE_FRAG } phase_t;

typedef struct {
  phase_t phase;

  // init (ftyp+moov)
  uint8_t *init_buf; size_t init_sz, init_cap;
  int have_ftyp, have_moov;

  // current fragment accumulation
  uint8_t *frag_buf; size_t frag_sz, frag_cap;

  // fragment parse state
  size_t frag_start;
  size_t need_moof;
  size_t need_mdat;
  int    seen_moof;
  int    collecting;

  // stats
  uint64_t out_init_once;
  uint64_t out_frags;
} splitter_t;

static void sp_init(splitter_t* s){
  memset(s,0,sizeof(*s));
  s->phase = PHASE_INIT;
}
static void sp_free(splitter_t* s){
  free(s->init_buf); free(s->frag_buf);
  memset(s,0,sizeof(*s));
}
static void buf_append(uint8_t **buf, size_t *sz, size_t *cap, const uint8_t *p, size_t n){
  if (*sz + n > *cap){ *cap = (*sz + n)*2 + 4096; *buf = (uint8_t*)realloc(*buf, *cap); }
  memcpy(*buf + *sz, p, n); *sz += n;
}
static size_t parse_box_size(const uint8_t *ptr, size_t avail, uint32_t *out_type){
  if (avail < 8) return 0;
  uint32_t sz = be32(ptr), ty = be32(ptr+4);
  if (sz == 0 || sz > avail) return 0;
  if (out_type) *out_type = ty; return sz;
}
static inline int is_leading_box(uint32_t ty){
  return ty == tagu("styp") || ty == tagu("sidx") || ty == tagu("prft") || ty == tagu("free");
}

// ---------- ta_mux_t ----------
typedef struct ta_mux {
  // ffmpeg
  AVCodecContext *enc;
  AVFormatContext *fmt;
  AVStream *st;
  AVIOContext *avio;
  uint8_t *avio_buf;
  int sr, ch;
  int64_t next_pts;
  enum AVSampleFormat enc_fmt;
  int frame_size;

  // resamplers
  SwrContext *swr_f32_to_enc; // f32 packed -> enc_fmt
  SwrContext *swr_s16_to_enc; // s16 packed -> enc_fmt

  // splitter
  splitter_t sp;

  // callbacks
  ta_mux_callbacks_t cbs;

  // FIFOs (frames)
  int16_t *fifo_s16; int s16_len, s16_cap;
  float   *fifo_f32; int f32_len, f32_cap;

  // stats
  uint64_t pkts_out;
} ta_mux_t;

// ---------- AVIO -> splitter ----------
static void sp_reset_frag(splitter_t* s){
  s->frag_sz = 0;
  s->frag_start = 0;
  s->need_moof = 0;
  s->need_mdat = 0;
  s->seen_moof = 0;
  s->collecting = 0;
}

static void sp_feed(ta_mux_t* m, const uint8_t *data, size_t len){
  splitter_t* s = &m->sp;
  size_t off = 0;
  TR_AVIO("avio->splitter: %zu bytes (phase=%s)", len, s->phase==PHASE_INIT?"INIT":"FRAG");

  while (off < len){
    size_t chunk = len - off;

    if (s->phase == PHASE_INIT){
      buf_append(&s->init_buf, &s->init_sz, &s->init_cap, data + off, chunk);
      off += chunk;

      size_t pos = 0;
      while (pos + 8 <= s->init_sz){
        uint32_t ty; size_t boxsz = parse_box_size(s->init_buf+pos, s->init_sz - pos, &ty);
        if (!boxsz) break;
        if (!s->have_ftyp && ty == tagu("ftyp")) s->have_ftyp = 1;
        else if (!s->have_moov && ty == tagu("moov")) s->have_moov = 1;
        pos += boxsz;

        if (s->have_ftyp && s->have_moov){
          LOGI("sp: init complete (ftyp+moov=%zu bytes)", pos);
          if (m->cbs.send_init) m->cbs.send_init(m->cbs.user, s->init_buf, pos);
          s->out_init_once++;
          size_t remain = s->init_sz - pos;
          s->init_sz = 0;
          s->phase = PHASE_FRAG;
          sp_reset_frag(s);
          if (remain) sp_feed(m, s->init_buf + pos, remain);
          return;
        }
      }
    } else {
      // PHASE_FRAG
      if (!s->collecting){
        s->frag_start = s->frag_sz;
        s->collecting = 1;
      }

      buf_append(&s->frag_buf, &s->frag_sz, &s->frag_cap, data + off, chunk);
      off += chunk;

      size_t pos = s->frag_start;
      while (pos + 8 <= s->frag_sz){
        uint32_t ty; size_t boxsz = parse_box_size(s->frag_buf + pos, s->frag_sz - pos, &ty);
        if (!boxsz) break;

        if (!s->seen_moof){
          if (ty == tagu("moof")){
            s->seen_moof = 1;
            s->need_moof = boxsz;
            TR_SPLIT("sp: moof size=%zu at pos=%zu", s->need_moof, pos);
            pos += boxsz;
            continue;
          }

          if (is_leading_box(ty)){
            TR_SPLIT("sp: leading box %c%c%c%c size=%zu",
                 (char)(ty>>24),(char)(ty>>16),(char)(ty>>8),(char)ty, boxsz);
            pos += boxsz;
            continue;
          }

          LOGW("sp: unexpected box before moof: 0x%08x — dropping and resync", ty);
          size_t consumed = pos + boxsz;
          if (consumed < s->frag_sz){
            memmove(s->frag_buf, s->frag_buf + consumed, s->frag_sz - consumed);
            s->frag_sz -= consumed;
          } else {
            s->frag_sz = 0;
          }
          sp_reset_frag(s);
          pos = 0;
          continue;
        } else {
          // already saw moof: scan forward until mdat, skipping any boxes in between
          if (ty == tagu("mdat")){
            s->need_mdat = boxsz;
            TR_SPLIT("sp: mdat size=%zu at pos=%zu", s->need_mdat, pos);

            if (pos + s->need_mdat > s->frag_sz) {
              // need more bytes for full mdat
              break;
            }

            // Emit from start of fragment (leading boxes) through end of this mdat
            size_t total = (pos - s->frag_start) + s->need_mdat;
            if (m->cbs.send_fragment) {
              m->cbs.send_fragment(m->cbs.user, s->frag_buf + s->frag_start, total);
            }
            s->out_frags++;
            LOGI("sp: sent fragment #%" PRIu64 " (%zu bytes)", s->out_frags, total);

            // Keep any tail after this fragment for the next one
            size_t tail_off = s->frag_start + total;
            size_t tail = (s->frag_sz > tail_off) ? (s->frag_sz - tail_off) : 0;
            if (tail){
              memmove(s->frag_buf, s->frag_buf + tail_off, tail);
            }
            s->frag_sz = tail;
            sp_reset_frag(s);
            pos = 0; // restart parsing in remaining buffer
            continue;
          }

          // Not mdat yet — include and continue scanning
          TR_SPLIT("sp: between moof & mdat: %c%c%c%c size=%zu",
               (char)(ty>>24),(char)(ty>>16),(char)(ty>>8),(char)ty, boxsz);
          pos += boxsz;
          continue;
        }
      }
    }
  }
}

// ---------- AVIO callbacks ----------
static int avio_write_cb(void* opaque, uint8_t* buf, int buf_size){
  TR_AVIO("avio_write_cb: %d bytes", buf_size);
  hexdump16(buf, buf_size);
  sp_feed((ta_mux_t*)opaque, buf, (size_t)buf_size);
  return buf_size;
}
static int64_t avio_seek_cb(void* opaque, int64_t offset, int whence){
  (void)opaque; (void)offset; (void)whence; return -1;
}

// ---------- format/layout helpers ----------
static enum AVSampleFormat choose_flac_sample_fmt(const AVCodec* codec){
  if (!codec->sample_fmts) return AV_SAMPLE_FMT_S16P;
  const enum AVSampleFormat *p = codec->sample_fmts;
  int has_s16p = 0, has_s16 = 0, has_s32p = 0;
  for (; *p != AV_SAMPLE_FMT_NONE; ++p){
    if (*p == AV_SAMPLE_FMT_S16P) has_s16p = 1;
    else if (*p == AV_SAMPLE_FMT_S16) has_s16 = 1;
    else if (*p == AV_SAMPLE_FMT_S32P) has_s32p = 1;
  }
  if (has_s16p) return AV_SAMPLE_FMT_S16P;
  if (has_s16 ) return AV_SAMPLE_FMT_S16;
  if (has_s32p) return AV_SAMPLE_FMT_S32P;
  return AV_SAMPLE_FMT_S16P;
}

static int set_audio_layout(AVCodecContext* enc, int channels){
#if LIBAVUTIL_VERSION_MAJOR >= 57
  if (channels == 2) {
    enc->ch_layout = (AVChannelLayout)AV_CHANNEL_LAYOUT_STEREO;
  } else {
    av_channel_layout_default(&enc->ch_layout, channels);
  }
  enc->channels       = channels;
  enc->channel_layout = (channels == 2) ? AV_CH_LAYOUT_STEREO : 0;
#else
  enc->channels       = channels;
  enc->channel_layout = (channels == 2)
                        ? AV_CH_LAYOUT_STEREO
                        : av_get_default_channel_layout(channels);
#endif
  return 0;
}

static int bprs_for_fmt(enum AVSampleFormat fmt){
  switch (fmt){
    case AV_SAMPLE_FMT_S16:
    case AV_SAMPLE_FMT_S16P: return 16;
    case AV_SAMPLE_FMT_S32:
    case AV_SAMPLE_FMT_S32P: return 24; // typical FLAC 24-bit in 32-bit container
    default: return 16;
  }
}

// ---------- FIFO helpers ----------
static void fifo_reserve_s16(struct ta_mux* m, int need_frames){
  if (need_frames <= m->s16_cap) return;
  int cap = m->s16_cap ? m->s16_cap : 4096;
  while (cap < need_frames) cap *= 2;
  m->fifo_s16 = (int16_t*)realloc(m->fifo_s16, (size_t)cap * m->ch * sizeof(int16_t));
  m->s16_cap = cap;
}
static void fifo_reserve_f32(struct ta_mux* m, int need_frames){
  if (need_frames <= m->f32_cap) return;
  int cap = m->f32_cap ? m->f32_cap : 4096;
  while (cap < need_frames) cap *= 2;
  m->fifo_f32 = (float*)realloc(m->fifo_f32, (size_t)cap * m->ch * sizeof(float));
  m->f32_cap = cap;
}

// ---------- encoding helpers ----------
static int write_encoded_packet(struct ta_mux* m){
  int ret; char ebuf[AV_ERROR_MAX_STRING_SIZE];
  for(;;){
    AVPacket pkt; av_init_packet(&pkt); pkt.data=NULL; pkt.size=0;
    ret = avcodec_receive_packet(m->enc, &pkt);
    if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) return 0;
    if (ret < 0) { LOGE("receive_packet: %s", errstr(ret, ebuf)); return ret; }

    pkt.duration = m->frame_size; // in 1/sr
    av_packet_rescale_ts(&pkt, (AVRational){1, m->sr}, m->st->time_base);
    pkt.duration = av_rescale_q(pkt.duration, (AVRational){1, m->sr}, m->st->time_base);

    int wr = av_interleaved_write_frame(m->fmt, &pkt);
    av_packet_unref(&pkt);
    if (wr < 0) { LOGE("write_frame: %s", errstr(wr, ebuf)); return wr; }

    m->pkts_out++;
    if ((m->pkts_out % 10) == 0) LOGI("packets out: %" PRIu64, m->pkts_out);
  }
}

static int encode_block_frame_ready(struct ta_mux* m, AVFrame* f){
  int ret; char ebuf[AV_ERROR_MAX_STRING_SIZE];
  f->pts = m->next_pts; m->next_pts += f->nb_samples;
  if ((ret = avcodec_send_frame(m->enc, f)) < 0) {
    LOGE("send_frame: %s", errstr(ret, ebuf)); return ret;
  }
  return write_encoded_packet(m);
}

static int encode_block_s16_interleaved(struct ta_mux* m, const int16_t* interleaved){
  int ret; char ebuf[AV_ERROR_MAX_STRING_SIZE];
  AVFrame *f = av_frame_alloc();
  if (!f) return AVERROR(ENOMEM);
  f->nb_samples = m->frame_size;
  f->sample_rate = m->sr;
  f->format = m->enc_fmt;
#if LIBAVUTIL_VERSION_MAJOR >= 57
  f->ch_layout = m->enc->ch_layout;
#else
  f->channels = m->ch;
  f->channel_layout = m->enc->channel_layout;
#endif
  if ((ret = av_frame_get_buffer(f, 0)) < 0) { LOGE("frame_get_buffer: %s", errstr(ret, ebuf)); av_frame_free(&f); return ret; }

  const uint8_t *in[1] = { (const uint8_t*)interleaved };
  if ((ret = swr_convert(m->swr_s16_to_enc, f->data, m->frame_size, in, m->frame_size)) != m->frame_size) {
    LOGE("swr_convert(S16->enc) ret=%d", ret);
    av_frame_free(&f); return (ret < 0) ? ret : AVERROR_EXTERNAL;
  }
  ret = encode_block_frame_ready(m, f);
  av_frame_free(&f);
  return ret;
}

static int encode_block_f32_interleaved(struct ta_mux* m, const float* interleaved){
  int ret; char ebuf[AV_ERROR_MAX_STRING_SIZE];
  AVFrame *f = av_frame_alloc();
  if (!f) return AVERROR(ENOMEM);
  f->nb_samples = m->frame_size;
  f->sample_rate = m->sr;
  f->format = m->enc_fmt;
#if LIBAVUTIL_VERSION_MAJOR >= 57
  f->ch_layout = m->enc->ch_layout;
#else
  f->channels = m->ch;
  f->channel_layout = m->enc->channel_layout;
#endif
  if ((ret = av_frame_get_buffer(f, 0)) < 0) { LOGE("frame_get_buffer: %s", errstr(ret, ebuf)); av_frame_free(&f); return ret; }

  const uint8_t *in[1] = { (const uint8_t*)interleaved };
  if ((ret = swr_convert(m->swr_f32_to_enc, f->data, m->frame_size, in, m->frame_size)) != m->frame_size) {
    LOGE("swr_convert(F32->enc) ret=%d", ret);
    av_frame_free(&f); return (ret < 0) ? ret : AVERROR_EXTERNAL;
  }
  ret = encode_block_frame_ready(m, f);
  av_frame_free(&f);
  return ret;
}

// ---------- API ----------
ta_mux_t* ta_mux_create_flac(int sample_rate, int channels, int frag_ms,
                             const ta_mux_callbacks_t* cbs)
{
  // read runtime logging config
  init_runtime_logging();

  av_log_set_level(AV_LOG_ERROR);

  ta_mux_t* m = (ta_mux_t*)calloc(1, sizeof(*m));
  if (!m) return NULL;
  m->sr = sample_rate; m->ch = channels; m->next_pts = 0;
  if (cbs) m->cbs = *cbs;
  sp_init(&m->sp);

  LOGI("create_flac: sr=%d ch=%d frag_ms=%d", sample_rate, channels, frag_ms);

  char ebuf[AV_ERROR_MAX_STRING_SIZE];
  int ret;

  const AVCodec *codec = avcodec_find_encoder(AV_CODEC_ID_FLAC);
  if (!codec) { LOGE("FLAC encoder not found"); goto fail; }

  m->enc = avcodec_alloc_context3(codec);
  if (!m->enc) { LOGE("avcodec_alloc_context3 failed"); goto fail; }

  m->enc_fmt = choose_flac_sample_fmt(codec);
  m->enc->sample_fmt = m->enc_fmt;
  m->enc->sample_rate = sample_rate;
  set_audio_layout(m->enc, channels);
  m->enc->bits_per_raw_sample = bprs_for_fmt(m->enc_fmt);

  // fastest encode
  av_opt_set_int(m->enc, "compression_level", 0, 0);
  // Optional “speed” hints; ignore if unsupported by build
  av_opt_set(m->enc, "lpc_type", "none", 0);
  av_opt_set(m->enc, "ch_mode", "indep", 0);
  av_opt_set_int(m->enc, "lpc_passes", 0, 0);
  av_opt_set_int(m->enc, "min_partition_order", 0, 0);
  av_opt_set_int(m->enc, "max_partition_order", 0, 0);

  LOGI("opening encoder: fmt=%s bprs=%d", av_get_sample_fmt_name(m->enc_fmt), m->enc->bits_per_raw_sample);
  if ((ret = avcodec_open2(m->enc, codec, NULL)) < 0) {
    LOGE("avcodec_open2: %s", errstr(ret, ebuf)); goto fail;
  }

  m->frame_size = m->enc->frame_size;
  if (m->frame_size <= 0) m->frame_size = 1024;
  LOGI("encoder frame_size=%d", m->frame_size);

  // Resamplers -> output exactly enc_fmt
  m->swr_f32_to_enc = swr_alloc();
#if LIBAVUTIL_VERSION_MAJOR >= 57
  av_opt_set_chlayout   (m->swr_f32_to_enc, "out_chlayout", &m->enc->ch_layout, 0);
  av_opt_set_chlayout   (m->swr_f32_to_enc, "in_chlayout",  &m->enc->ch_layout, 0);
#else
  av_opt_set_int        (m->swr_f32_to_enc, "out_channel_layout", m->enc->channel_layout, 0);
  av_opt_set_int        (m->swr_f32_to_enc, "in_channel_layout",  m->enc->channel_layout, 0);
#endif
  av_opt_set_int        (m->swr_f32_to_enc, "out_sample_rate", m->sr, 0);
  av_opt_set_sample_fmt (m->swr_f32_to_enc, "out_sample_fmt", m->enc_fmt, 0);
  av_opt_set_int        (m->swr_f32_to_enc, "in_sample_rate", m->sr, 0);
  av_opt_set_sample_fmt (m->swr_f32_to_enc, "in_sample_fmt",  AV_SAMPLE_FMT_FLT, 0);
  if (!m->swr_f32_to_enc || (ret = swr_init(m->swr_f32_to_enc)) < 0) { LOGE("swr_init f32->enc: %s", errstr(ret, ebuf)); goto fail; }

  m->swr_s16_to_enc = swr_alloc();
#if LIBAVUTIL_VERSION_MAJOR >= 57
  av_opt_set_chlayout   (m->swr_s16_to_enc, "out_chlayout", &m->enc->ch_layout, 0);
  av_opt_set_chlayout   (m->swr_s16_to_enc, "in_chlayout",  &m->enc->ch_layout, 0);
#else
  av_opt_set_int        (m->swr_s16_to_enc, "out_channel_layout", m->enc->channel_layout, 0);
  av_opt_set_int        (m->swr_s16_to_enc, "in_channel_layout",  m->enc->channel_layout, 0);
#endif
  av_opt_set_int        (m->swr_s16_to_enc, "out_sample_rate", m->sr, 0);
  av_opt_set_sample_fmt (m->swr_s16_to_enc, "out_sample_fmt", m->enc_fmt, 0);
  av_opt_set_int        (m->swr_s16_to_enc, "in_sample_rate", m->sr, 0);
  av_opt_set_sample_fmt (m->swr_s16_to_enc, "in_sample_fmt",  AV_SAMPLE_FMT_S16, 0);
  if (!m->swr_s16_to_enc || (ret = swr_init(m->swr_s16_to_enc)) < 0) { LOGE("swr_init s16->enc: %s", errstr(ret, ebuf)); goto fail; }

  // -------- Container / muxer ----------
  {
    int r = avformat_alloc_output_context2(&m->fmt, NULL, "mp4", NULL);
    if (r < 0 || !m->fmt) {
      LOGE("alloc_output_context2(mp4): %s", errstr(r, ebuf));
      goto fail;
    }

    // movflags (no +dash), then low-latency knobs
    try_set_movflags(m->fmt->priv_data);
    opt_set_str(m->fmt->priv_data, "brand", "isom");
    opt_set_str(m->fmt->priv_data, "compatible_brands", "isom,mp42,iso5");

    // Low-latency fragment duration in microseconds: force ~40ms
    {
      char fragdur[32];
      snprintf(fragdur, sizeof(fragdur), "%d", 40 * 1000);
      opt_set_str(m->fmt->priv_data, "frag_duration", fragdur);
    }

    opt_set_int(m->fmt->priv_data, "flush_packets", 1);
    opt_set_int(m->fmt->priv_data, "max_interleave_delta", 0);
    opt_set_int(m->fmt->priv_data, "use_editlist", 0);
    opt_set_int(m->fmt->priv_data, "write_prft", 0);

    m->st = avformat_new_stream(m->fmt, NULL);
    if (!m->st) { LOGE("new_stream failed"); goto fail; }

    r = avcodec_parameters_from_context(m->st->codecpar, m->enc);
    if (r < 0) { LOGE("params_from_context: %s", errstr(r, ebuf)); goto fail; }

    LOGI("codecpar: codec_id=%d extradata=%p size=%d",
         m->st->codecpar->codec_id,
         (void*)m->st->codecpar->extradata,
         m->st->codecpar->extradata_size);

    m->st->time_base = (AVRational){1, m->sr};

    // AVIO buffer: 2 KB to flush early
    int avio_buf_sz = 2*1024;
    m->avio_buf = (uint8_t*)av_malloc(avio_buf_sz);
    m->avio = avio_alloc_context(m->avio_buf, avio_buf_sz, 1, m, NULL, avio_write_cb, avio_seek_cb);
    if (!m->avio) { LOGE("avio_alloc_context failed"); goto fail; }
    m->fmt->pb = m->avio;

    LOGI("writing header...");
    r = avformat_write_header(m->fmt, NULL);
    if (r < 0) {
      LOGE("write_header failed: %s", errstr(r, ebuf));
      goto fail;
    }
    LOGI("header written (init will be emitted)");
  }

  fifo_reserve_s16(m, m->frame_size * 2);
  fifo_reserve_f32(m, m->frame_size * 2);
  return m;

fail:
  ta_mux_close(m);
  return NULL;
}

int ta_mux_push_pcm_s16(ta_mux_t* m, const int16_t* interleaved, int frames){
  if (!m || !interleaved || frames <= 0) return -1;
  fifo_reserve_s16(m, m->s16_len + frames);
  memcpy(m->fifo_s16 + (size_t)m->s16_len * m->ch, interleaved, (size_t)frames * m->ch * sizeof(int16_t));
  m->s16_len += frames;

  int produced = 0;
  while (m->s16_len >= m->frame_size){
    int ret = encode_block_s16_interleaved(m, m->fifo_s16);
    if (ret < 0) return ret;
    int left = (m->s16_len - m->frame_size) * m->ch;
    memmove(m->fifo_s16, m->fifo_s16 + (size_t)m->frame_size * m->ch, (size_t)left * sizeof(int16_t));
    m->s16_len -= m->frame_size;
    produced++;
  }
  TR_PUSH("push_s16: produced=%d frame_size=%d fifo_left=%d", produced, m->frame_size, m->s16_len);
  return 0;
}

int ta_mux_push_pcm_f32(ta_mux_t* m, const float* interleaved, int frames){
  if (!m || !interleaved || frames <= 0) return -1;
  fifo_reserve_f32(m, m->f32_len + frames);
  memcpy(m->fifo_f32 + (size_t)m->f32_len * m->ch, interleaved, (size_t)frames * m->ch * sizeof(float));
  m->f32_len += frames;

  int produced = 0;
  while (m->f32_len >= m->frame_size){
    int ret = encode_block_f32_interleaved(m, m->fifo_f32);
    if (ret < 0) return ret;
    int left = (m->f32_len - m->frame_size) * m->ch;
    memmove(m->fifo_f32, m->fifo_f32 + (size_t)m->frame_size * m->ch, (size_t)left * sizeof(float));
    m->f32_len -= m->frame_size;
    produced++;
  }
  TR_PUSH("push_f32: produced=%d frame_size=%d fifo_left=%d", produced, m->frame_size, m->f32_len);
  return 0;
}

void ta_mux_close(ta_mux_t* m){
  if (!m) return;
  LOGI("closing mux...");
  if (m->fmt) { av_write_trailer(m->fmt); LOGI("trailer written"); }
  if (m->avio){ av_freep(&m->avio->buffer); avio_context_free(&m->avio); }
  if (m->fmt){ avformat_free_context(m->fmt); }
  if (m->enc){ avcodec_free_context(&m->enc); }
  if (m->swr_f32_to_enc){ swr_free(&m->swr_f32_to_enc); }
  if (m->swr_s16_to_enc){ swr_free(&m->swr_s16_to_enc); }
  if (m->fifo_s16) free(m->fifo_s16);
  if (m->fifo_f32) free(m->fifo_f32);
  LOGI("stats: pkts_out=%" PRIu64 " init=%" PRIu64 " frags=%" PRIu64, m->pkts_out, m->sp.out_init_once, m->sp.out_frags);
  sp_free(&m->sp);
  free(m);
}
