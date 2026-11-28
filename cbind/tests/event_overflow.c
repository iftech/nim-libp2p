// A blocked listener fills the event queue: pubsub drops past 3/4 of it,
// inbound streams take the last quarter, and requests still work.
#include "../examples/common.h"

#ifndef EVENT_QUEUE_CAPACITY
#error "build with -DEVENT_QUEUE_CAPACITY=<the library's EventQueueCapacity>"
#endif

#define PUBSUB_DROP_DEPTH (EVENT_QUEUE_CAPACITY * 3 / 4)
#define STREAM_HEADROOM (EVENT_QUEUE_CAPACITY - PUBSUB_DROP_DEPTH)

static const char *Topic = "/cbind/overflow";
static const char *Proto = "/cbind/overflow/1.0.0";
static const int Overflow = 3;
static const int64_t ReadTimeoutMs = 2000;

static atomic_int g_block = 1;
static atomic_int g_delivered = 0;
static atomic_int g_incoming = 0;

static void onPubsubMessage(const PubsubMessageEvent *evt, void *ud) {
  (void)evt;
  (void)ud;
  atomic_fetch_add(&g_delivered, 1);
  while (atomic_load(&g_block))
    sleep_ms(10);
}

static void onIncomingStream(const IncomingStreamEvent *evt, void *ud) {
  (void)evt;
  (void)ud;
  atomic_fetch_add(&g_incoming, 1);
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
} PublishWaiter;

static void on_publish(int ec, const PublishResponse *reply, const char *em,
                       void *ud) {
  (void)reply;
  PublishWaiter *w = (PublishWaiter *)ud;
  w->err_code = ec;
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char json[1 << 18];
} MetricsWaiter;

static MetricsWaiter g_metrics;

static void on_metrics(int ec, const NimFfiStr *reply, const char *em,
                       void *ud) {
  MetricsWaiter *w = (MetricsWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data) {
    size_t n =
        reply->len < sizeof(w->json) - 1 ? reply->len : sizeof(w->json) - 1;
    memcpy(w->json, reply->data, n);
    w->json[n] = '\0';
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// A sample's own "value" is the first one after its labels' closing ']'.
static long dropped(const char *label) {
  memset(&g_metrics, 0, sizeof(g_metrics));
  libp2p_static_collect_metrics(on_metrics, &g_metrics);
  wait_done(&g_metrics.done);
  if (g_metrics.err_code != 0) {
    fprintf(stderr, "collect_metrics: %s\n", g_metrics.err);
    return -1;
  }

  char want[64];
  snprintf(want, sizeof(want), "\"%s\"", label);
  for (const char *p = g_metrics.json;
       (p = strstr(p, "libp2p_cbind_events_dropped")) != NULL; p++) {
    const char *close = strchr(p, ']');
    const char *hit = strstr(p, want);
    if (!close || !hit || hit > close)
      continue;
    const char *v = strstr(close, "\"value\":");
    return v ? (long)strtod(v + strlen("\"value\":"), NULL) : -1;
  }
  return 0;
}

static bool expectDropped(const char *label, long want) {
  long got = dropped(label);
  if (got != want) {
    fprintf(stderr, "dropped %s: want %ld, got %ld\n", label, want, got);
    return false;
  }
  printf("dropped %s: %ld\n", label, got);
  return true;
}

static LibP2PCtx *createNode(const char *label, bool gossipsub) {
  NimFfiStr addrSlot = nimffi_str("/ip4/127.0.0.1/tcp/0");
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.gossipsub.mount = gossipsub;
  cfg.gossipsub.triggerSelf = gossipsub;
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP;
  return await_create(&cfg, label);
}

static bool publishPastCapacity(LibP2PCtx *node) {
  for (int i = 0; i < EVENT_QUEUE_CAPACITY + Overflow; i++) {
    char msg[32];
    snprintf(msg, sizeof(msg), "message-%d", i);
    PublishRequest req = {nimffi_str(Topic), {(uint8_t *)msg, strlen(msg)}};
    PublishWaiter w;
    memset(&w, 0, sizeof(w));
    libp2p_ctx_gossipsub_publish(node, &req, on_publish, &w);
    wait_done(&w.done);
    if (w.err_code != 0) {
      fprintf(stderr, "publish %d: %s\n", i, w.err);
      return false;
    }
  }
  return true;
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  uint64_t streamId;
} DialWaiter;

static void on_dial(int ec, const DialResponse *reply, const char *em,
                    void *ud) {
  DialWaiter *w = (DialWaiter *)ud;
  w->err_code = ec;
  if (reply)
    w->streamId = reply->streamId;
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static void on_read(int ec, const ReadResponse *reply, const char *em,
                    void *ud) {
  (void)reply;
  on_bool(ec, NULL, em, ud);
}

static bool dial(LibP2PCtx *client, const PeerInfoWaiter *pw,
                 uint64_t *streamId) {
  NimFfiStr addrs[MAX_ADDRS];
  for (size_t i = 0; i < pw->naddrs; i++)
    addrs[i] = nimffi_str(pw->addrs[i]);
  DialRequest req = {
      nimffi_str(pw->peerId), nimffi_str(Proto), {addrs, pw->naddrs}, false, 0};
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  libp2p_ctx_dial(client, &req, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial: %s\n", dw.err);
    return false;
  }
  *streamId = dw.streamId;
  return true;
}

// Close reads the optimistic echo, which unread stalls the mplex reader.
static bool closeWrite(LibP2PCtx *client, uint64_t streamId) {
  BoolWaiter bw;
  return AWAIT_BOOL(bw, libp2p_ctx_stream_close(client, streamId, on_bool, &bw),
                    "close");
}

static bool release(LibP2PCtx *client, uint64_t streamId) {
  BoolWaiter bw;
  return AWAIT_BOOL(
      bw, libp2p_ctx_stream_release(client, streamId, on_bool, &bw), "release");
}

// The pubsub flood leaves STREAM_HEADROOM slots; the stream past them resets.
static bool streamsUseHeadroom(LibP2PCtx *client, LibP2PCtx *server) {
  PeerInfoWaiter pw;
  if (!await_peerinfo(server, &pw, "server peerinfo"))
    return false;

  uint64_t held[STREAM_HEADROOM];
  int nheld = 0;
  bool ok = true;
  while (ok && nheld < STREAM_HEADROOM)
    if ((ok = dial(client, &pw, &held[nheld])))
      ok = closeWrite(client, held[nheld++]);
  ok = ok && expectDropped("incoming_stream", 0);

  uint64_t last;
  if (ok && (ok = dial(client, &pw, &last))) {
    BoolWaiter rw;
    memset(&rw, 0, sizeof(rw));
    StreamReadExactlyRequest read = {last, 1, ReadTimeoutMs};
    libp2p_ctx_stream_read_exactly(client, &read, on_read, &rw);
    wait_done(&rw.done);
    if (rw.err_code == 0 || strcmp(rw.err, "read timeout") == 0) {
      fprintf(stderr, "read past the headroom: want a reset, got %d \"%s\"\n",
              rw.err_code, rw.err);
      ok = false;
    }
    ok = release(client, last) && ok;
    ok = ok && expectDropped("incoming_stream", 1);
  }

  for (int i = 0; i < nheld; i++)
    ok = release(client, held[i]) && ok;
  return ok;
}

static bool waitCount(const char *what, atomic_int *n, int want) {
  for (int i = 0; i < 500 && atomic_load(n) < want; i++)
    sleep_ms(10);
  sleep_ms(200);
  int got = atomic_load(n);
  if (got != want) {
    fprintf(stderr, "%s: want %d, got %d\n", what, want, got);
    return false;
  }
  printf("%s: %d\n", what, got);
  return true;
}

static bool deliversDropDepth(void) {
  atomic_store(&g_block, 0);
  bool ok = waitCount("delivered", &g_delivered, PUBSUB_DROP_DEPTH);
  return waitCount("incoming streams", &g_incoming, STREAM_HEADROOM) && ok;
}

int main(void) {
  LibP2PCtx *server = createNode("server", true);
  LibP2PCtx *client = createNode("client", false);
  if (!server || !client) {
    libp2p_ctx_destroy(server);
    libp2p_ctx_destroy(client);
    return EXIT_FAILURE;
  }
  libp2p_ctx_add_on_pubsub_message_listener(server, onPubsubMessage, NULL);
  libp2p_ctx_add_on_incoming_stream_listener(server, onIncomingStream, NULL);

  bool ok = false;
  BoolWaiter bw;
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_gossipsub_subscribe(server, nimffi_str(Topic),
                                                 on_bool, &bw),
                  "subscribe") ||
      !AWAIT_BOOL(
          bw,
          libp2p_ctx_mount_protocol(server, nimffi_str(Proto), on_bool, &bw),
          "mount_protocol") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(server, on_bool, &bw), "start server") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(client, on_bool, &bw), "start client"))
    goto cleanup;

  ok = publishPastCapacity(server);
  ok = ok && expectDropped("pubsub_message",
                           EVENT_QUEUE_CAPACITY + Overflow - PUBSUB_DROP_DEPTH);
  ok = ok && streamsUseHeadroom(client, server);
  ok = deliversDropDepth() && ok;

cleanup:
  atomic_store(&g_block, 0);
  AWAIT_BOOL(bw, libp2p_ctx_stop(client, on_bool, &bw), "stop client");
  AWAIT_BOOL(bw, libp2p_ctx_stop(server, on_bool, &bw), "stop server");
  libp2p_ctx_destroy(client);
  libp2p_ctx_destroy(server);
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
