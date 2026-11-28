// Peerstore: a node's local record of other peers. This drives the store
// directly — no dialing — using a second node's real PeerInfo: add the peer,
// list it, read it back, then delete it. Calls are made blocking via common.h.
#include "common.h"

static const char *Proto = "/cbind/peerstore/1.0.0";

// get_peers replies with a PeersResponse of peer-id strings.
#define MAX_PEERS 16
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  char peerIds[MAX_PEERS][128];
  size_t n;
} PeersWaiter;

static void on_peers(int ec, const PeersResponse *reply, const char *em,
                     void *ud) {
  PeersWaiter *w = (PeersWaiter *)ud;
  w->err_code = ec;
  if (reply) {
    w->n = reply->peerIds.len < MAX_PEERS ? reply->peerIds.len : MAX_PEERS;
    for (size_t i = 0; i < w->n; i++)
      if (reply->peerIds.data[i].data)
        snprintf(w->peerIds[i], sizeof(w->peerIds[i]), "%s",
                 reply->peerIds.data[i].data);
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static bool get_peers(LibP2PCtx *ctx, PeersWaiter *w) {
  memset(w, 0, sizeof(*w));
  libp2p_ctx_peerstore_get_peers(ctx, on_peers, w);
  wait_done(&w->done);
  if (w->err_code != 0) {
    fprintf(stderr, "get_peers: %s\n", w->err[0] ? w->err : "unknown");
    return false;
  }
  return true;
}

static bool holds(const PeersWaiter *w, const char *peerId) {
  for (size_t i = 0; i < w->n; i++)
    if (strcmp(w->peerIds[i], peerId) == 0)
      return true;
  return false;
}

// get_peer_info replies with the full entry; we only report its counts here.
typedef struct {
  atomic_int done;
  int err_code;
  char err[256];
  size_t naddrs, nprotocols;
} EntryWaiter;

static void on_entry(int ec, const PeerStoreEntryResponse *reply,
                     const char *em, void *ud) {
  EntryWaiter *w = (EntryWaiter *)ud;
  w->err_code = ec;
  if (reply) {
    w->naddrs = reply->addrs.len;
    w->nprotocols = reply->protocols.len;
  }
  if (em)
    snprintf(w->err, sizeof(w->err), "%s", em);
  atomic_store(&w->done, 1);
}

static LibP2PCtx *createNode(const char *addr, const char *label) {
  NimFfiStr slot = nimffi_str(addr);
  Libp2pConfig cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.addrs.data = &slot;
  cfg.addrs.len = 1;
  cfg.muxer = MUXER_TYPE_MPLEX;
  cfg.transports = TRANSPORT_TCP;
  return await_create(&cfg, label);
}

int main(void) {
  int status = 1;
  BoolWaiter bw;

  // `local` owns the peerstore we drive; `other` just hands us a real peer id
  // and listen addresses to store.
  LibP2PCtx *local = createNode("/ip4/127.0.0.1/tcp/5051", "local");
  LibP2PCtx *other = createNode("/ip4/127.0.0.1/tcp/5052", "other");
  if (!local || !other) {
    libp2p_ctx_destroy(local);
    libp2p_ctx_destroy(other);
    return 1;
  }

  // Start `other` so its listen addresses are bound and reported by peer_info.
  if (!AWAIT_BOOL(bw, libp2p_ctx_start(other, on_bool, &bw), "start other"))
    goto cleanup;
  PeerInfoWaiter oi;
  if (!await_peerinfo(other, &oi, "other peerinfo"))
    goto cleanup;
  printf("Peer to store: %s\n", oi.peerId);

  // add_peer: merge the peer's addresses and a protocol into the store.
  NimFfiStr addrs[MAX_ADDRS];
  for (size_t i = 0; i < oi.naddrs; i++)
    addrs[i] = nimffi_str(oi.addrs[i]);
  NimFfiStr proto = nimffi_str(Proto);
  AddPeerRequest addReq = {
      nimffi_str(oi.peerId), {addrs, oi.naddrs}, {&proto, 1}};
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_peerstore_add_peer(local, &addReq, on_bool, &bw),
                  "add_peer"))
    goto cleanup;

  // get_peers + get_peer_info: the peer is now listed and readable.
  PeersWaiter peers;
  if (!get_peers(local, &peers))
    goto cleanup;
  EntryWaiter entry;
  memset(&entry, 0, sizeof(entry));
  libp2p_ctx_peerstore_get_peer_info(local, nimffi_str(oi.peerId), on_entry,
                                     &entry);
  wait_done(&entry.done);
  if (entry.err_code != 0) {
    fprintf(stderr, "get_peer_info: %s\n",
            entry.err[0] ? entry.err : "unknown");
    goto cleanup;
  }
  printf("Stored: %zu peer(s), entry has %zu address(es) and %zu protocol(s)\n",
         peers.n, entry.naddrs, entry.nprotocols);
  if (!holds(&peers, oi.peerId) || entry.naddrs == 0 || entry.nprotocols == 0) {
    fprintf(stderr, "Error: peer was not stored correctly\n");
    goto cleanup;
  }

  // delete_peer: the store no longer holds it.
  if (!AWAIT_BOOL(bw,
                  libp2p_ctx_peerstore_delete_peer(local, nimffi_str(oi.peerId),
                                                   on_bool, &bw),
                  "delete_peer"))
    goto cleanup;
  if (!get_peers(local, &peers))
    goto cleanup;
  if (holds(&peers, oi.peerId)) {
    fprintf(stderr, "Error: peer still present after delete_peer\n");
    goto cleanup;
  }
  printf("Deleted %s\n", oi.peerId);
  status = 0;

cleanup:
  AWAIT_BOOL(bw, libp2p_ctx_stop(other, on_bool, &bw), "stop other");
  libp2p_ctx_destroy(other);
  libp2p_ctx_destroy(local);
  return status;
}
