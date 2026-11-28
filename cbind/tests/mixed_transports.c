// A host with TCP and QUIC enabled connects to a TCP-only and a QUIC-only peer.
#include "../examples/common.h"

static LibP2PCtx *createNode(const char *label, const char *addr,
                             int transports) {
  NimFfiStr addrSlot = nimffi_str(addr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &addrSlot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = transports;
  cfg.dialRanking = true;
  return await_create(&cfg, label);
}

static LibP2PCtx *createMixedNode(void) {
  NimFfiStr addrs[2] = {nimffi_str("/ip4/127.0.0.1/tcp/0"),
                        nimffi_str("/ip4/127.0.0.1/udp/0/quic-v1")};
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = addrs;
  cfg.addrs.len = 2;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP | TRANSPORT_QUIC;
  cfg.dialRanking = true;
  return await_create(&cfg, "mixed");
}

static bool startNode(LibP2PCtx *ctx, const char *label) {
  BoolWaiter bw;
  return AWAIT_BOOL(bw, libp2p_ctx_start(ctx, on_bool, &bw), label);
}

static bool mixedDialsBothPeers(LibP2PCtx *mixed, LibP2PCtx *tcpOnly,
                                LibP2PCtx *quicOnly) {
  PeerInfoWaiter tcpInfo, quicInfo, mixedInfo;
  if (!await_peerinfo(tcpOnly, &tcpInfo, "tcp peer info") ||
      !await_peerinfo(quicOnly, &quicInfo, "quic peer info") ||
      !await_peerinfo(mixed, &mixedInfo, "mixed peer info"))
    return false;
  return await_connect(mixed, &tcpInfo) && await_connect(mixed, &quicInfo) &&
         await_connect(tcpOnly, &mixedInfo) &&
         await_connect(quicOnly, &mixedInfo);
}

int main(void) {
  LibP2PCtx *mixed = createMixedNode();
  LibP2PCtx *tcpOnly =
      createNode("tcp only", "/ip4/127.0.0.1/tcp/0", TRANSPORT_TCP);
  LibP2PCtx *quicOnly =
      createNode("quic only", "/ip4/127.0.0.1/udp/0/quic-v1", TRANSPORT_QUIC);
  bool ok = false;
  BoolWaiter bw;
  if (mixed && tcpOnly && quicOnly && startNode(mixed, "start mixed") &&
      startNode(tcpOnly, "start tcp only") &&
      startNode(quicOnly, "start quic only"))
    ok = mixedDialsBothPeers(mixed, tcpOnly, quicOnly);

  LibP2PCtx *nodes[] = {mixed, tcpOnly, quicOnly};
  for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); i++) {
    if (!nodes[i])
      continue;
    AWAIT_BOOL(bw, libp2p_ctx_stop(nodes[i], on_bool, &bw), "stop");
    libp2p_ctx_destroy(nodes[i]);
  }
  return ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
