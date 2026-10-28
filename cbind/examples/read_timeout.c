// Stream reads with a timeout, one at a time, against a peer that never writes.
#include "common.h"

static const char *SilentProto = "/cbind/silent/1.0.0";
static const int64_t ReadMaxSize = 4096;
static const int64_t ShortTimeoutMs = 100;
static const int64_t LongTimeoutMs = 2000;

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
  size_t len;
  uint8_t first;
} ReadWaiter;

static void on_read(int ec, const ReadResponse *reply, const char *em,
                    void *ud) {
  ReadWaiter *w = (ReadWaiter *)ud;
  w->err_code = ec;
  if (reply && reply->data.len > 0) {
    w->len = reply->data.len;
    w->first = reply->data.data[0];
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static bool expectReadError(ReadWaiter *w, const char *want,
                            const char *label) {
  wait_done(&w->done);
  if (w->err_code == 0 || strcmp(w->err, want) != 0) {
    fprintf(stderr, "%s: want error \"%s\", got code %d \"%s\"\n", label, want,
            w->err_code, w->err);
    return false;
  }
  printf("%s: %s\n", label, w->err);
  return true;
}

static bool expectReadFailsFast(ReadWaiter *w, const char *label) {
  wait_done(&w->done);
  if (w->err_code == 0 || strcmp(w->err, "read timeout") == 0) {
    fprintf(stderr, "%s: want a reset error, got code %d \"%s\"\n", label,
            w->err_code, w->err);
    return false;
  }
  printf("%s: %s\n", label, w->err);
  return true;
}

static bool expectReadByte(ReadWaiter *w, uint8_t want, const char *label) {
  wait_done(&w->done);
  if (w->err_code != 0 || w->len != 1 || w->first != want) {
    fprintf(stderr, "%s: want byte %c, got code %d len %zu \"%s\"\n", label,
            want, w->err_code, w->len, w->err);
    return false;
  }
  printf("%s: read %c\n", label, w->first);
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

static bool openSilentStream(LibP2PCtx *client, const DialRequest *dialReq,
                             uint64_t *clientId, uint64_t *serverId) {
  DialWaiter dw;
  memset(&dw, 0, sizeof(dw));
  libp2p_ctx_dial(client, dialReq, on_dial, &dw);
  wait_done(&dw.done);
  if (dw.err_code != 0) {
    fprintf(stderr, "dial: %s\n", dw.err[0] ? dw.err : "unknown");
    return false;
  }
  wait_done(&g_have_stream);
  atomic_store(&g_have_stream, 0);
  *clientId = dw.streamId;
  *serverId = g_stream_id;
  return true;
}

static void releaseBoth(LibP2PCtx *client, uint64_t clientId, LibP2PCtx *server,
                        uint64_t serverId) {
  BoolWaiter bw;
  AWAIT_BOOL(bw, libp2p_ctx_stream_release(client, clientId, on_bool, &bw),
             "client release");
  AWAIT_BOOL(bw, libp2p_ctx_stream_release(server, serverId, on_bool, &bw),
             "server release");
}

static bool readTimesOut(LibP2PCtx *client, LibP2PCtx *server,
                         const DialRequest *dialReq) {
  uint64_t clientId, serverId;
  if (!openSilentStream(client, dialReq, &clientId, &serverId))
    return false;

  ReadWaiter rw;
  memset(&rw, 0, sizeof(rw));
  StreamReadLpRequest req = {clientId, ReadMaxSize, ShortTimeoutMs};
  libp2p_ctx_stream_read_lp(client, &req, on_read, &rw);
  bool ok = expectReadError(&rw, "read timeout", "read_lp with 100 ms");

  ReadWaiter after;
  memset(&after, 0, sizeof(after));
  StreamReadLpRequest afterReq = {clientId, ReadMaxSize, LongTimeoutMs};
  libp2p_ctx_stream_read_lp(client, &afterReq, on_read, &after);
  bool resetOk = expectReadFailsFast(&after, "read_lp after timeout");
  ok = ok && resetOk;

  releaseBoth(client, clientId, server, serverId);
  return ok;
}

static bool secondReadRejected(LibP2PCtx *client, LibP2PCtx *server,
                               const DialRequest *dialReq) {
  uint64_t clientId, serverId;
  if (!openSilentStream(client, dialReq, &clientId, &serverId))
    return false;

  ReadWaiter first, second;
  memset(&first, 0, sizeof(first));
  memset(&second, 0, sizeof(second));
  StreamReadExactlyRequest firstReq = {clientId, 1, LongTimeoutMs};
  StreamReadExactlyRequest secondReq = {clientId, 1, ShortTimeoutMs};
  libp2p_ctx_stream_read_exactly(client, &firstReq, on_read, &first);
  libp2p_ctx_stream_read_exactly(client, &secondReq, on_read, &second);
  bool secondOk =
      expectReadError(&second, "read already in progress", "second read");
  bool firstOk = expectReadError(&first, "read timeout", "first read");
  bool ok = secondOk && firstOk;

  releaseBoth(client, clientId, server, serverId);
  return ok;
}

static bool writeByte(LibP2PCtx *ctx, uint64_t id, uint8_t *byte) {
  BoolWaiter bw;
  NimFfiBytes data = {byte, 1};
  StreamWriteRequest req = {id, data};
  return AWAIT_BOOL(bw, libp2p_ctx_stream_write(ctx, &req, on_bool, &bw),
                    "stream_write");
}

static bool readAcceptedAfterSuccess(LibP2PCtx *client, LibP2PCtx *server,
                                     const DialRequest *dialReq) {
  uint64_t clientId, serverId;
  if (!openSilentStream(client, dialReq, &clientId, &serverId))
    return false;

  uint8_t byte = 'k';
  ReadWaiter first, second;
  memset(&first, 0, sizeof(first));
  memset(&second, 0, sizeof(second));
  StreamReadExactlyRequest req = {clientId, 1, LongTimeoutMs};
  StreamReadExactlyRequest again = {clientId, 1, ShortTimeoutMs};
  libp2p_ctx_stream_read_exactly(client, &req, on_read, &first);
  bool wrote = writeByte(server, serverId, &byte);
  bool firstOk = expectReadByte(&first, 'k', "first read");
  libp2p_ctx_stream_read_exactly(client, &again, on_read, &second);
  bool againOk = expectReadError(&second, "read timeout", "read after success");
  bool ok = wrote && firstOk && againOk;

  releaseBoth(client, clientId, server, serverId);
  return ok;
}

static bool readOnReleasedStreamFails(LibP2PCtx *client, LibP2PCtx *server,
                                      const DialRequest *dialReq) {
  uint64_t clientId, serverId;
  if (!openSilentStream(client, dialReq, &clientId, &serverId))
    return false;
  releaseBoth(client, clientId, server, serverId);

  ReadWaiter lp, exact;
  memset(&lp, 0, sizeof(lp));
  memset(&exact, 0, sizeof(exact));
  StreamReadLpRequest lpReq = {clientId, ReadMaxSize, ShortTimeoutMs};
  StreamReadExactlyRequest exactReq = {clientId, 1, ShortTimeoutMs};
  libp2p_ctx_stream_read_lp(client, &lpReq, on_read, &lp);
  libp2p_ctx_stream_read_exactly(client, &exactReq, on_read, &exact);
  bool lpOk = expectReadError(&lp, "unknown stream handle", "read_lp released");
  bool exactOk =
      expectReadError(&exact, "unknown stream handle", "read_exactly released");
  return lpOk && exactOk;
}

static LibP2PCtx *createNode(const char *label) {
  NimFfiStr addrSlot = nimffi_str("/ip4/127.0.0.1/tcp/0");
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transport = TRANSPORT_TYPE_TCP;
  return await_create(&cfg, label);
}

int main(void) {
  LibP2PCtx *server = createNode("server");
  if (!server)
    return 1;

  libp2p_ctx_add_on_incoming_stream_listener(server, onIncomingStream, NULL);

  BoolWaiter bw;
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_mount_protocol(server, nimffi_str(SilentProto),
                                            on_bool, &bw),
                  "mount_protocol") ||
      !AWAIT_BOOL(bw, libp2p_ctx_start(server, on_bool, &bw), "start server")) {
    libp2p_ctx_destroy(server);
    return 1;
  }

  PeerInfoWaiter pw;
  if (!await_peerinfo(server, &pw, "peerinfo")) {
    libp2p_ctx_destroy(server);
    return 1;
  }

  LibP2PCtx *client = createNode("client");
  if (!client) {
    libp2p_ctx_destroy(server);
    return 1;
  }

  int status = 1;
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(client, on_bool, &bw), "start client"))
    goto cleanup;

  NimFfiStr dialAddrs[MAX_ADDRS];
  for (size_t i = 0; i < pw.naddrs; i++)
    dialAddrs[i] = nimffi_str(pw.addrs[i]);
  DialRequest dialReq = {nimffi_str(pw.peerId),
                         nimffi_str(SilentProto),
                         {dialAddrs, pw.naddrs},
                         false,
                         0};
  if (readTimesOut(client, server, &dialReq) &&
      secondReadRejected(client, server, &dialReq) &&
      readAcceptedAfterSuccess(client, server, &dialReq) &&
      readOnReleasedStreamFails(client, server, &dialReq))
    status = 0;

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(client, on_bool, &bw), "stop client");
  AWAIT_BOOL(bw, libp2p_ctx_stop(server, on_bool, &bw), "stop server");
  libp2p_ctx_destroy(client);
  libp2p_ctx_destroy(server);
  return status;
}
