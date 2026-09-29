# to allow locking
if dirExists("nimbledeps/pkgs2"):
  switch("NimblePath", "nimbledeps/pkgs2")

switch("warningAsError", "BareExcept:on")
switch("warningAsError", "CaseTransition:on")
switch("warningAsError", "CStringConv:on")
switch("warningAsError", "ImplicitDefaultValue:on")
switch("warningAsError", "LockLevel:on")
switch("warningAsError", "ObservableStores:on")
switch("warningAsError", "ProveField:on")
switch("warningAsError", "ResultShadowed:on")
switch("warningAsError", "UnreachableCode:on")
switch("warningAsError", "UnreachableElse:on")
switch("warningAsError", "UnusedImport:on")
switch("warningAsError", "UseBase:on")
switch("hintAsError", "ConvFromXtoItselfNotNeeded:on")
switch("hintAsError", "DuplicateModuleImport:on")
switch("hintAsError", "XCannotRaiseY:on")

--styleCheck:
  usages
--styleCheck:
  error
--mm:
  refc
  # TODO: evaluate switching to orc on the version-2-2 branch

# Avoid some rare stack corruption while using exceptions with a SEH-enabled
# toolchain: https://github.com/status-im/nimbus-eth2/issues/3121
if defined(windows) and not defined(vcc):
  --define:
    nimRawSetjmp

# begin Nimble config (version 2)
when withDir(thisDir(), system.fileExists("nimble.paths")):
  include "nimble.paths"
# end Nimble config
