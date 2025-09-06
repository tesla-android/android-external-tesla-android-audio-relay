#pragma once
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
  void (*send_init)(void* user, const uint8_t* data, size_t len);
  void (*send_fragment)(void* user, const uint8_t* data, size_t len);
  void* user;
} ta_mux_callbacks_t;

typedef struct ta_mux ta_mux_t;

/** Create a FLAC-in-fragmented-MP4 muxer (outputs via callbacks). */
ta_mux_t* ta_mux_create_flac(int sample_rate, int channels, int frag_ms,
                             const ta_mux_callbacks_t* cbs);

/** Push S16 interleaved (L,R,...) frames. */
int ta_mux_push_pcm_s16(ta_mux_t* m, const int16_t* interleaved, int frames);

/** Push Float32 interleaved (L,R,...) frames. */
int ta_mux_push_pcm_f32(ta_mux_t* m, const float* interleaved, int frames);

/** Destroy muxer. Safe on NULL. */
void ta_mux_close(ta_mux_t* m);

#ifdef __cplusplus
}
#endif
