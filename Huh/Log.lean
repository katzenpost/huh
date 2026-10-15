/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.FFI

/-! # Server logging

The server logs to stderr, which systemd sends to the journal, or to syslog with `--syslog`. -/

namespace Huh

def logInfo : UInt32 := 6
def logWarning : UInt32 := 4

def log (toSyslog : Bool) (prio : UInt32) (msg : String) : IO Unit :=
  if toSyslog then FFI.syslog prio msg else IO.eprintln msg

end Huh
