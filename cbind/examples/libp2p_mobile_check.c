// SPDX-License-Identifier: Apache-2.0 OR MIT
// Copyright (c) Status Research & Development GmbH

#include <errno.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "libp2p.h"

enum { CALLBACK_TIMEOUT_SECONDS = 20 };

typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  int done;
  int err_code;
  char err_msg[512];
  LibP2PCtx *ctx;
  bool bool_reply;
} CallbackWait;

static void wait_init(CallbackWait *wait) {
  memset(wait, 0, sizeof(*wait));
  wait->err_code = NIMFFI_RET_OK;
  if (pthread_mutex_init(&wait->mutex, NULL) != 0) {
    fprintf(stderr, "pthread_mutex_init failed\n");
    exit(2);
  }
  if (pthread_cond_init(&wait->cond, NULL) != 0) {
    fprintf(stderr, "pthread_cond_init failed\n");
    exit(2);
  }
}

static void wait_destroy(CallbackWait *wait) {
  pthread_cond_destroy(&wait->cond);
  pthread_mutex_destroy(&wait->mutex);
}

static void record_error(CallbackWait *wait, int err_code,
                         const char *err_msg) {
  wait->err_code = err_code;
  if (err_msg != NULL && err_msg[0] != '\0') {
    snprintf(wait->err_msg, sizeof(wait->err_msg), "%s", err_msg);
  } else if (err_code != NIMFFI_RET_OK) {
    snprintf(wait->err_msg, sizeof(wait->err_msg), "FFI returned error code %d",
             err_code);
  }
}

static void signal_done(CallbackWait *wait) {
  wait->done = 1;
  pthread_cond_signal(&wait->cond);
}

static void on_created(int err_code, LibP2PCtx *ctx, const char *err_msg,
                       void *user_data) {
  CallbackWait *wait = (CallbackWait *)user_data;
  pthread_mutex_lock(&wait->mutex);
  record_error(wait, err_code, err_msg);
  if (err_code == NIMFFI_RET_OK && ctx == NULL) {
    record_error(wait, -1, "create callback returned a null context");
  } else {
    wait->ctx = ctx;
  }
  signal_done(wait);
  pthread_mutex_unlock(&wait->mutex);
}

static void on_bool_reply(int err_code, const bool *reply, const char *err_msg,
                          void *user_data) {
  CallbackWait *wait = (CallbackWait *)user_data;
  pthread_mutex_lock(&wait->mutex);
  record_error(wait, err_code, err_msg);
  if (err_code == NIMFFI_RET_OK && reply == NULL) {
    record_error(wait, -1, "bool callback returned a null reply");
  } else if (reply != NULL) {
    wait->bool_reply = *reply;
  }
  signal_done(wait);
  pthread_mutex_unlock(&wait->mutex);
}

static int wait_for_callback(CallbackWait *wait, const char *op) {
  struct timespec deadline;
  if (clock_gettime(CLOCK_REALTIME, &deadline) != 0) {
    fprintf(stderr, "%s: clock_gettime failed: %s\n", op, strerror(errno));
    exit(EXIT_FAILURE);
  }
  deadline.tv_sec += CALLBACK_TIMEOUT_SECONDS;

  pthread_mutex_lock(&wait->mutex);
  int rc = 0;
  while (!wait->done && rc == 0) {
    rc = pthread_cond_timedwait(&wait->cond, &wait->mutex, &deadline);
  }

  int err_code = wait->err_code;
  char err_msg[sizeof(wait->err_msg)];
  snprintf(err_msg, sizeof(err_msg), "%s", wait->err_msg);
  pthread_mutex_unlock(&wait->mutex);

  if (rc == ETIMEDOUT) {
    fprintf(stderr, "%s: timed out after %d seconds\n", op,
            CALLBACK_TIMEOUT_SECONDS);
    // A late callback still owns the stack waiter and its synchronization
    // state.
    exit(EXIT_FAILURE);
  }
  if (rc != 0) {
    fprintf(stderr, "%s: pthread_cond_timedwait failed: %s\n", op,
            strerror(rc));
    exit(EXIT_FAILURE);
  }
  if (err_code != NIMFFI_RET_OK) {
    fprintf(stderr, "%s: %s\n", op,
            err_msg[0] ? err_msg : "FFI callback failed");
    return 1;
  }
  return 0;
}

static int create_node(LibP2PCtx **out_ctx) {
  Libp2pConfig config;
  memset(&config, 0, sizeof(config));

  NimFfiStr listen_addrs[] = {nimffi_str("/ip4/127.0.0.1/tcp/0")};
  config.addrs.data = listen_addrs;
  config.addrs.len = 1;
  config.dnsResolver = nimffi_str("");
  config.transports = TRANSPORT_TCP;
  config.muxer = MUXER_TYPE_YAMUX;
  config.maxConnections = 8;
  config.maxIn = 4;
  config.maxOut = 4;
  config.maxConnsPerPeer = 2;

  CallbackWait create_wait;
  wait_init(&create_wait);
  int submit = libp2p_ctx_create(&config, on_created, &create_wait);
  if (submit != 0) {
    fprintf(stderr, "create: submit failed\n");
    wait_destroy(&create_wait);
    return 1;
  }
  if (wait_for_callback(&create_wait, "create") != 0) {
    if (create_wait.ctx != NULL) {
      libp2p_ctx_destroy(create_wait.ctx);
    }
    wait_destroy(&create_wait);
    return 1;
  }

  *out_ctx = create_wait.ctx;
  wait_destroy(&create_wait);
  return 0;
}

static int call_bool_method(
    const char *op, LibP2PCtx *ctx,
    int (*fn)(const LibP2PCtx *,
              void (*)(int, const bool *, const char *, void *), void *)) {
  CallbackWait wait;
  wait_init(&wait);
  int submit = fn(ctx, on_bool_reply, &wait);
  if (submit != 0) {
    fprintf(stderr, "%s: submit failed\n", op);
    wait_destroy(&wait);
    return 1;
  }
  if (wait_for_callback(&wait, op) != 0) {
    wait_destroy(&wait);
    return 1;
  }
  if (!wait.bool_reply) {
    fprintf(stderr, "%s: expected true reply\n", op);
    wait_destroy(&wait);
    return 1;
  }
  wait_destroy(&wait);
  return 0;
}

int main(void) {
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  LibP2PCtx *ctx = NULL;
  if (create_node(&ctx) != 0) {
    return 1;
  }

  int rc = 0;
  if (call_bool_method("start", ctx, libp2p_ctx_start) != 0) {
    rc = 1;
    goto cleanup;
  }
  if (call_bool_method("stop", ctx, libp2p_ctx_stop) != 0) {
    rc = 1;
    goto cleanup;
  }

cleanup:
  // ctx_destroy reports teardown status; a smoke check should fail on it.
  if (libp2p_ctx_destroy(ctx) != NIMFFI_RET_OK) {
    fprintf(stderr, "destroy: context teardown failed\n");
    rc = 1;
  }
  return rc;
}
