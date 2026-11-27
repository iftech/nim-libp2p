// GossipSub pub/sub: two TCP nodes connect on a shared topic and exchange one
// message, delivered to the subscriber via its pubsub-message listener. The
// generated bindings are asynchronous, so each call is wrapped with the
// blocking helpers in common.h.
#include "common.h"

static const char *Topic = "/cbind/demo";

static atomic_int g_got = 0;
static char g_received[512];

// gossipsub_publish replies with a PublishResponse carrying the number of peers
// the message was forwarded to, so it needs its own waiter rather than on_bool.
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  int64_t peerCount;
} PublishWaiter;

static void on_publish(int ec, const PublishResponse *reply, const char *em,
                       void *ud) {
  PublishWaiter *w = (PublishWaiter *)ud;
  w->err_code = ec;
  if (reply)
    w->peerCount = reply->peerCount;
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static void onPubsubMessage(const PubsubMessageEvent *evt, void *ud) {
  (void)ud;
  size_t len = evt->data.len < sizeof(g_received) - 1 ? evt->data.len
                                                      : sizeof(g_received) - 1;
  if (evt->data.data)
    memcpy(g_received, evt->data.data, len);
  g_received[len] = '\0';
  atomic_store(&g_got, 1);
}

static LibP2PCtx *gossipsubNode(const char *listenAddr, const char *label) {
  NimFfiStr addrSlot = nimffi_str(listenAddr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.gossipsub.mount = true;
  cfg.gossipsub.triggerSelf = true;
  // Bound the inbound side: one message is at most 1 MiB, and a peer gets
  // 64 KiB of protocol overhead per second. The budget only counts overhead
  // until disconnectPeerAboveRateLimit enforces it, which this demo leaves off
  // so a slow CI runner cannot drop its own peer.
  cfg.gossipsub.maxMessageSize = 1024 * 1024;
  cfg.gossipsub.overheadRateLimit.bytes = 64 * 1024;
  cfg.gossipsub.overheadRateLimit.intervalMs = 1000;
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP;
  return await_create(&cfg, label);
}

int main(void) {
  LibP2PCtx *subscriber =
      gossipsubNode("/ip4/127.0.0.1/tcp/5021", "subscriber");
  LibP2PCtx *publisher = gossipsubNode("/ip4/127.0.0.1/tcp/5022", "publisher");
  if (!subscriber || !publisher) {
    libp2p_ctx_destroy(subscriber);
    libp2p_ctx_destroy(publisher);
    return 1;
  }

  int status = 1;
  BoolWaiter bw;

  libp2p_ctx_add_on_pubsub_message_listener(subscriber, onPubsubMessage, NULL);

  // Both peers subscribe so a GossipSub mesh can form between them.
  LibP2PCtx *nodes[2] = {subscriber, publisher};
  for (int i = 0; i < 2; i++) {
    if (!AWAIT_BOOL(bw,
                    libp2p_ctx_gossipsub_subscribe(nodes[i], nimffi_str(Topic),
                                                   on_bool, &bw),
                    "subscribe") ||
        !AWAIT_BOOL(bw, libp2p_ctx_start(nodes[i], on_bool, &bw), "start"))
      goto cleanup;
  }

  PeerInfoWaiter pw;
  if (!await_peerinfo(subscriber, &pw, "peerinfo"))
    goto cleanup;
  printf("Subscriber: %s\n", pw.peerId);

  NimFfiStr connAddrs[MAX_ADDRS];
  for (size_t i = 0; i < pw.naddrs; i++)
    connAddrs[i] = nimffi_str(pw.addrs[i]);
  ConnectRequest connReq = {nimffi_str(pw.peerId), {connAddrs, pw.naddrs}, 0};
  if (!AWAIT_BOOL(bw, libp2p_ctx_connect(publisher, &connReq, on_bool, &bw),
                  "connect"))
    goto cleanup;

  // Give the subscription time to propagate and the mesh to graft before
  // publishing.
  sleep_ms(2000);

  const char *message = "hello gossipsub";
  printf("Publishing: %s\n", message);
  NimFfiBytes payload = {(uint8_t *)message, strlen(message)};
  PublishRequest pubReq = {nimffi_str(Topic), payload};
  PublishWaiter pubw;
  memset(&pubw, 0, sizeof(pubw));
  libp2p_ctx_gossipsub_publish(publisher, &pubReq, on_publish, &pubw);
  wait_done(&pubw.done);
  if (pubw.err_code != 0) {
    fprintf(stderr, "publish: %s\n", pubw.err[0] ? pubw.err : "unknown");
    goto cleanup;
  }
  printf("Published to %lld peer(s)\n", (long long)pubw.peerCount);

  wait_done(&g_got);
  printf("Subscriber received: %s\n", g_received);
  status = strcmp(g_received, message) == 0 ? 0 : 1;

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(publisher, on_bool, &bw), "stop publisher");
  AWAIT_BOOL(bw, libp2p_ctx_stop(subscriber, on_bool, &bw), "stop subscriber");
  libp2p_ctx_destroy(publisher);
  libp2p_ctx_destroy(subscriber);
  return status;
}
