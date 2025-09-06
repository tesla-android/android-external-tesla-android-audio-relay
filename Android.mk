LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := tesla-android-audio-relay
LOCAL_VENDOR_MODULE := true        # link against vendor libs
LOCAL_MULTILIB := first            # build one arch (64 on 64-bit products)

LOCAL_SRC_FILES := \
    tesla-android-audio-relay.c \
    ta_audio_mux.c

LOCAL_CFLAGS += -D__STDC_FORMAT_MACROS -Wno-deprecated-declarations
LOCAL_LDLIBS +=
LOCAL_SHARED_LIBRARIES := \
    libcutils \
    libavformat \
    libavcodec \
    libavutil \
    libswresample \
    liblog \
    libws

include $(BUILD_EXECUTABLE)
