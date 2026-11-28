// Circuit relay: a relay, a destination and a source. The destination reserves
// a slot on the relay (circuit_relay_reserve); the source then reaches it over
// a /p2p-circuit address (dial_circuit_relay) and sends one message, which the
// destination reads off its relayed stream. As in echo.c the destination serves
// its incoming stream from main. Calls are made blocking via common.h.
#include "common.h"

static const char *Proto = "/cbind/relay/1.0.0";

// Single-slot hand-off from the destination's incoming-stream event to main.
static atomic_int g_have_stream = 0;
static uint64_t g_stream_id = 0;

static void onIncomingStream(const IncomingStreamEvent *evt, void *ud) {
  (void)ud;
  g_stream_id = evt->streamId;
  atomic_store(&g_have_stream, 1);
}

typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  uint8_t data[4096];
  size_t len;
} ReadWaiter;

static void on_read(int ec, const ReadResponse *reply, const char *em,
                    void *ud) {
  ReadWaiter *w = (ReadWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data.data) {
    w->len =
        reply->data.len < sizeof(w->data) ? reply->data.len : sizeof(w->data);
    memcpy(w->data, reply->data.data, w->len);
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
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

// reserve replies with a ReservationResponse we don't inspect; reuse
// BoolWaiter.
static void on_reserve(int ec, const ReservationResponse *reply, const char *em,
                       void *ud) {
  (void)reply;
  BoolWaiter *w = (BoolWaiter *)ud;
  w->err_code = ec;
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

// The relay is a circuit-relay server; source and destination are relay clients
// so they can reserve slots and dial /p2p-circuit addresses.
static LibP2PCtx *createNode(const char *addr, const char *label, bool client) {
  NimFfiStr slot = nimffi_str(addr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &slot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP;
  cfg.circuitRelay = !client;
  cfg.circuitRelayClient = client;
  return await_create(&cfg, label);
}

int main(void) {
  int status = 1;
  BoolWaiter bw;

  LibP2PCtx *relay = createNode("/ip4/127.0.0.1/tcp/5061", "relay", false);
  LibP2PCtx *dst = createNode("/ip4/127.0.0.1/tcp/5062", "dst", true);
  LibP2PCtx *src = createNode("/ip4/127.0.0.1/tcp/5063", "src", true);
  if (!relay || !dst || !src) {
    libp2p_ctx_destroy(relay);
    libp2p_ctx_destroy(dst);
    libp2p_ctx_destroy(src);
    return 1;
  }

  libp2p_ctx_add_on_incoming_stream_listener(dst, onIncomingStream, NULL);

  if (!AWAIT_BOOL(
          bw, libp2p_ctx_mount_protocol(dst, nimffi_str(Proto), on_bool, &bw),
          "mount") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(relay, on_bool, &bw), "start relay") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(dst, on_bool, &bw), "start dst") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(src, on_bool, &bw), "start src"))
    goto cleanup;

  PeerInfoWaiter relayInfo, dstInfo;
  if (!await_peerinfo(relay, &relayInfo, "relay peerinfo") ||
      !await_peerinfo(dst, &dstInfo, "dst peerinfo") || relayInfo.naddrs == 0)
    goto cleanup;
  printf("Relay: %s\nDst:   %s\n", relayInfo.peerId, dstInfo.peerId);

  // Dst connects to the relay and reserves a slot so the relay forwards circuit
  // traffic addressed to it.
  NimFfiStr relayAddrs[MAX_ADDRS];
  for (size_t i = 0; i < relayInfo.naddrs; i++)
    relayAddrs[i] = nimffi_str(relayInfo.addrs[i]);
  ConnectRequest connReq = {
      nimffi_str(relayInfo.peerId), {relayAddrs, relayInfo.naddrs}, 0};
  if (!AWAIT_BOOL(bw, libp2p_ctx_connect(dst, &connReq, on_bool, &bw),
                  "dst -> relay"))
    goto cleanup;
  CircuitRelayReserveRequest resReq = {nimffi_str(relayInfo.peerId),
                                       {relayAddrs, relayInfo.naddrs}};
  if (!AWAIT_BOOL(
          bw, libp2p_ctx_circuit_relay_reserve(dst, &resReq, on_reserve, &bw),
          "reserve"))
    goto cleanup;

  // Circuit address: the relay's transport address, its peer id, /p2p-circuit.
  // Dialing it connects the source to the relay implicitly.
  char circuit[512];
  snprintf(circuit, sizeof(circuit), "%s/p2p/%s/p2p-circuit",
           relayInfo.addrs[0], relayInfo.peerId);
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  DialCircuitRelayRequest dialReq = {nimffi_str(dstInfo.peerId),
                                     nimffi_str(circuit), nimffi_str(Proto), 0};
  libp2p_ctx_dial_circuit_relay(src, &dialReq, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial_circuit_relay: %s\n", dw.err[0] ? dw.err : "unknown");
    goto cleanup;
  }

  const char *msg = "hello over the relay";
  printf("Src sending via %s: %s\n", circuit, msg);
  NimFfiBytes bytes = {(uint8_t *)msg, strlen(msg)};
  StreamWriteRequest wr = {dw.streamId, bytes};
  if (!AWAIT_BOOL(bw, libp2p_ctx_stream_write_lp(src, &wr, on_bool, &bw),
                  "write"))
    goto cleanup;

  // Dst serves its relayed stream from this thread: read and verify.
  wait_done(&g_have_stream);
  ReadWaiter rw;
  memset(&rw, 0, sizeof(rw));
  StreamReadLpRequest rd = {g_stream_id, 4096};
  libp2p_ctx_stream_read_lp(dst, &rd, on_read, &rw);
  wait_done(&rw.done);
  if (rw.err_code != 0) {
    fprintf(stderr, "dst read: %s\n", rw.err[0] ? rw.err : "unknown");
    goto cleanup;
  }
  printf("Dst received: %.*s\n", (int)rw.len, (const char *)rw.data);
  if (rw.len == strlen(msg) && memcmp(rw.data, msg, rw.len) == 0)
    status = 0;
  else
    fprintf(stderr, "Error: relayed message did not match\n");
  AWAIT_BOOL(bw, libp2p_ctx_stream_release(dst, g_stream_id, on_bool, &bw),
             "dst release");

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(src, on_bool, &bw), "stop src");
  AWAIT_BOOL(bw, libp2p_ctx_stop(dst, on_bool, &bw), "stop dst");
  AWAIT_BOOL(bw, libp2p_ctx_stop(relay, on_bool, &bw), "stop relay");
  libp2p_ctx_destroy(src);
  libp2p_ctx_destroy(dst);
  libp2p_ctx_destroy(relay);
  return status;
}
