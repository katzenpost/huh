/-
SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
SPDX-License-Identifier: AGPL-3.0-only
-/

/-! # The C shim: process spawning, PTYs, raw fds and terminal modes -/

namespace Huh.FFI

/-- A child on a new PTY in its own session: `(pid, master fd)`. -/
@[extern "huh_spawn_pty"]
opaque spawnPty (path : @& String) (argv envp : @& Array String) (dir : @& String)
  (rows cols : UInt16) : IO (UInt32 × UInt32)

/-- A child on three pipes in its own session: `(pid, stdin, stdout, stderr)`. -/
@[extern "huh_spawn_pipes"]
opaque spawnPipes (path : @& String) (argv envp : @& Array String) (dir : @& String) :
  IO (UInt32 × UInt32 × UInt32 × UInt32)

/-- Up to `n` bytes; empty at end of stream. -/
@[extern "huh_read"] opaque read (fd : UInt32) (n : USize) : IO ByteArray
@[extern "huh_write"] opaque write (fd : UInt32) (bytes : @& ByteArray) : IO Unit
@[extern "huh_close"] opaque close (fd : UInt32) : IO Unit
@[extern "huh_pty_resize"] opaque ptyResize (fd : UInt32) (rows cols : UInt16) : IO Unit

/-- Signal a child's process group by name, such as `"INT"`; `false` for an unknown name. -/
@[extern "huh_kill_group"] opaque killGroup (pid : UInt32) (name : @& String) : IO Bool

/-- `(code, "")` after a normal exit, or `(0, signal name)`. -/
@[extern "huh_wait"] opaque wait (pid : UInt32) : IO (UInt32 × String)

/-- Put a terminal in raw mode, returning its previous state. -/
@[extern "huh_tty_raw"] opaque ttyRaw (fd : UInt32) : IO ByteArray
@[extern "huh_tty_restore"] opaque ttyRestore (fd : UInt32) (saved : @& ByteArray) : IO Unit
/-- `(rows, cols)`. -/
@[extern "huh_tty_winsize"] opaque ttyWinsize (fd : UInt32) : IO (UInt16 × UInt16)
@[extern "huh_isatty"] opaque isatty (fd : UInt32) : IO Bool
/-- Print `prompt` on `/dev/tty` and read a line from it with echo off. -/
@[extern "huh_read_passphrase"] opaque readPassphrase (prompt : @& String) : IO String

/-- `(user, home, shell)` of the effective user. -/
@[extern "huh_getpw"] opaque getpw : IO (String × String × String)
/-- Owned by us and unreadable by anyone else. -/
@[extern "huh_file_private"] opaque filePrivate (path : @& String) : IO Bool
@[extern "huh_syslog"] opaque syslog (prio : UInt32) (msg : @& String) : IO Unit
@[extern "huh_ignore_sigpipe"] opaque ignoreSigpipe : IO Unit

end Huh.FFI
