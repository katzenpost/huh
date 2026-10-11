/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

import Huh.FFI

/-! # Server logging

Under inetd stderr is the connection, so the server logs to syslog unless told stderr is safe:
by `-e`, or by systemd setting `JOURNAL_STREAM`. -/

namespace Huh

def logInfo : UInt32 := 6
def logWarning : UInt32 := 4

def log (toStderr : Bool) (prio : UInt32) (msg : String) : IO Unit := do
  if toStderr || (← IO.getEnv "JOURNAL_STREAM").isSome then IO.eprintln msg
  else FFI.syslog prio msg

end Huh
