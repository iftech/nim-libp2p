import ../../config.nims

# stdout carries only the interop contract lines (LOCAL, READY, PEER, SENT,
# RECV, INTEROP_OK), so Chronicles logs from the library go to stderr.
switch("define", "chronicles_sinks=textlines[stderr]")
