/*
 * SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
 * SPDX-License-Identifier: AGPL-3.0-only
 */

#include <lean/lean.h>

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <termios.h>
#include <unistd.h>

static lean_obj_res io_errno_at(b_lean_obj_arg fname) {
  return lean_io_result_mk_error(lean_decode_io_error(errno, fname));
}

static lean_obj_res io_errno(void) {
  lean_object *none = lean_mk_string("");
  lean_obj_res r = io_errno_at(none);
  lean_dec(none);
  return r;
}

static lean_obj_res io_user_error(const char *msg) {
  return lean_io_result_mk_error(lean_mk_io_user_error(lean_mk_string(msg)));
}

static lean_obj_res io_unit(void) { return lean_io_result_mk_ok(lean_box(0)); }

static lean_obj_res pair(lean_obj_arg a, lean_obj_arg b) {
  lean_object *p = lean_alloc_ctor(0, 2, 0);
  lean_ctor_set(p, 0, a);
  lean_ctor_set(p, 1, b);
  return p;
}

static char **cstrings(b_lean_obj_arg arr) {
  size_t n = lean_array_size(arr);
  char **out = malloc((n + 1) * sizeof(char *));
  if (out == NULL) return NULL;
  for (size_t i = 0; i < n; i++)
    out[i] = (char *)lean_string_cstr(lean_array_get_core(arr, i));
  out[n] = NULL;
  return out;
}

static const struct { const char *name; int sig; } signals[] = {
  {"HUP", SIGHUP}, {"INT", SIGINT}, {"QUIT", SIGQUIT}, {"ILL", SIGILL}, {"ABRT", SIGABRT},
  {"FPE", SIGFPE}, {"KILL", SIGKILL}, {"SEGV", SIGSEGV}, {"PIPE", SIGPIPE}, {"ALRM", SIGALRM},
  {"TERM", SIGTERM}, {"USR1", SIGUSR1}, {"USR2", SIGUSR2}, {"BUS", SIGBUS}, {"TSTP", SIGTSTP},
  {"CONT", SIGCONT}, {"WINCH", SIGWINCH},
};

static int signal_number(const char *name) {
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
    if (strcmp(signals[i].name, name) == 0) return signals[i].sig;
  return -1;
}

static const char *signal_name(int sig) {
  for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); i++)
    if (signals[i].sig == sig) return signals[i].name;
  return "UNKNOWN";
}

static void close_range_fallback(int first, int last) {
#ifdef __linux__
  if (syscall(436 /* close_range */, (unsigned)first, (unsigned)last, 0) == 0) return;
#endif
  for (int fd = first; fd <= last; fd++) close(fd);
}

/* Closes every fd from 3 up except `keep`. */
static void close_others(int keep, long maxfd) {
  if (keep > 3) close_range_fallback(3, keep - 1);
#ifdef __linux__
  if (syscall(436, (unsigned)keep + 1, ~0U, 0) == 0) return;
#endif
  close_range_fallback(keep + 1, (int)maxfd - 1);
}

static void child_fail(int errfd) {
  int e = errno;
  ssize_t ignored = write(errfd, &e, sizeof(e));
  (void)ignored;
  _exit(127);
}

/* Runs in the forked child: only async-signal-safe calls from here to execve. `errfd` is
   close-on-exec, so the parent reads end of file once execve succeeds, or an errno before. */
static void child_exec(const char *slave, int in, int out, int err, int errfd, long maxfd,
                       const char *dir, const char *path, char **argv, char **envp) {
  if (setsid() < 0) child_fail(errfd);
  if (slave != NULL) {
    int fd = open(slave, O_RDWR);
    if (fd < 0) child_fail(errfd);
#ifdef TIOCSCTTY
    if (ioctl(fd, TIOCSCTTY, 0) < 0) child_fail(errfd);
#endif
    in = out = err = fd;
  }
  if (dup2(in, 0) < 0 || dup2(out, 1) < 0 || dup2(err, 2) < 0) child_fail(errfd);
  close_others(errfd, maxfd);
  sigset_t none;
  sigemptyset(&none);
  sigprocmask(SIG_SETMASK, &none, NULL);
  struct sigaction dfl;
  memset(&dfl, 0, sizeof(dfl));
  dfl.sa_handler = SIG_DFL;
  for (int s = 1; s < NSIG; s++) sigaction(s, &dfl, NULL);
  if (chdir(dir) < 0 && chdir("/") < 0) child_fail(errfd);
  execve(path, argv, envp);
  child_fail(errfd);
}

static lean_obj_res spawn(b_lean_obj_arg path, b_lean_obj_arg argv, b_lean_obj_arg envp,
                          b_lean_obj_arg dir, int pty, uint16_t rows, uint16_t cols) {
  char **cargv = cstrings(argv), **cenvp = cstrings(envp);
  if (cargv == NULL || cenvp == NULL) {
    free(cargv);
    free(cenvp);
    return io_user_error("out of memory");
  }
  int master = -1, fds[6] = {-1, -1, -1, -1, -1, -1}, errpipe[2] = {-1, -1};
  char slave[256];
  if (pty) {
    master = posix_openpt(O_RDWR | O_NOCTTY | O_CLOEXEC);
    struct winsize ws = {.ws_row = rows, .ws_col = cols};
    if (master < 0 || grantpt(master) < 0 || unlockpt(master) < 0 ||
        ptsname_r(master, slave, sizeof(slave)) != 0 || ioctl(master, TIOCSWINSZ, &ws) < 0)
      goto fail;
  } else {
    for (int i = 0; i < 3; i++)
      if (pipe2(fds + 2 * i, O_CLOEXEC) < 0) goto fail;
  }
  if (pipe2(errpipe, O_CLOEXEC) < 0) goto fail;
  long maxfd = sysconf(_SC_OPEN_MAX);
  if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
  pid_t pid = fork();
  if (pid < 0) goto fail;
  if (pid == 0)
    child_exec(pty ? slave : NULL, fds[0], fds[3], fds[5], errpipe[1], maxfd,
               lean_string_cstr(dir), lean_string_cstr(path), cargv, cenvp);
  close(errpipe[1]);
  errpipe[1] = -1;
  int childErr = 0;
  ssize_t r;
  do r = read(errpipe[0], &childErr, sizeof(childErr));
  while (r < 0 && errno == EINTR);
  if (r == sizeof(childErr)) {
    while (waitpid(pid, NULL, 0) < 0 && errno == EINTR) {}
    errno = childErr;
    goto fail;
  }
  close(errpipe[0]);
  free(cargv);
  free(cenvp);
  lean_object *pidObj = lean_box_uint32((uint32_t)pid);
  if (pty) return lean_io_result_mk_ok(pair(pidObj, lean_box_uint32((uint32_t)master)));
  close(fds[0]);
  close(fds[3]);
  close(fds[5]);
  return lean_io_result_mk_ok(pair(pidObj,
      pair(lean_box_uint32((uint32_t)fds[1]),
           pair(lean_box_uint32((uint32_t)fds[2]), lean_box_uint32((uint32_t)fds[4])))));
fail:;
  int saved = errno;
  if (master >= 0) close(master);
  for (int i = 0; i < 6; i++)
    if (fds[i] >= 0) close(fds[i]);
  for (int i = 0; i < 2; i++)
    if (errpipe[i] >= 0) close(errpipe[i]);
  free(cargv);
  free(cenvp);
  errno = saved;
  return io_errno_at(path);
}

LEAN_EXPORT lean_obj_res huh_spawn_pty(b_lean_obj_arg path, b_lean_obj_arg argv,
                                       b_lean_obj_arg envp, b_lean_obj_arg dir,
                                       uint16_t rows, uint16_t cols) {
  return spawn(path, argv, envp, dir, 1, rows, cols);
}

LEAN_EXPORT lean_obj_res huh_spawn_pipes(b_lean_obj_arg path, b_lean_obj_arg argv,
                                         b_lean_obj_arg envp, b_lean_obj_arg dir) {
  return spawn(path, argv, envp, dir, 0, 0, 0);
}

/* An empty result is end of stream; a PTY master reports that as EIO once the slave closes. */
LEAN_EXPORT lean_obj_res huh_read(uint32_t fd, size_t n) {
  lean_object *buf = lean_alloc_sarray(1, 0, n);
  ssize_t r;
  do r = read((int)fd, lean_sarray_cptr(buf), n);
  while (r < 0 && errno == EINTR);
  if (r < 0 && errno != EIO) {
    lean_dec(buf);
    return io_errno();
  }
  lean_to_sarray(buf)->m_size = r < 0 ? 0 : (size_t)r;
  return lean_io_result_mk_ok(buf);
}

LEAN_EXPORT lean_obj_res huh_write(uint32_t fd, b_lean_obj_arg bytes) {
  const uint8_t *p = lean_sarray_cptr(bytes);
  size_t left = lean_sarray_size(bytes);
  while (left > 0) {
    ssize_t w = write((int)fd, p, left);
    if (w < 0) {
      if (errno == EINTR) continue;
      return io_errno();
    }
    p += w;
    left -= (size_t)w;
  }
  return io_unit();
}

LEAN_EXPORT lean_obj_res huh_close(uint32_t fd) {
  if (close((int)fd) < 0 && errno != EINTR) return io_errno();
  return io_unit();
}

LEAN_EXPORT lean_obj_res huh_pty_resize(uint32_t fd, uint16_t rows, uint16_t cols) {
  struct winsize ws = {.ws_row = rows, .ws_col = cols};
  if (ioctl((int)fd, TIOCSWINSZ, &ws) < 0) return io_errno();
  return io_unit();
}

/* Signals the child's whole process group; false for a signal name we don't know. */
LEAN_EXPORT lean_obj_res huh_kill_group(uint32_t pid, b_lean_obj_arg name) {
  int sig = signal_number(lean_string_cstr(name));
  if (sig < 0) return lean_io_result_mk_ok(lean_box(0));
  if (kill(-(pid_t)pid, sig) < 0 && errno != ESRCH) return io_errno();
  return lean_io_result_mk_ok(lean_box(1));
}

/* (exit code, "") for a normal exit, (0, signal name) for death by signal. */
LEAN_EXPORT lean_obj_res huh_wait(uint32_t pid) {
  int status;
  pid_t r;
  do r = waitpid((pid_t)pid, &status, 0);
  while (r < 0 && errno == EINTR);
  if (r < 0) return io_errno();
  if (WIFSIGNALED(status))
    return lean_io_result_mk_ok(pair(lean_box_uint32(0), lean_mk_string(signal_name(WTERMSIG(status)))));
  return lean_io_result_mk_ok(pair(lean_box_uint32((uint32_t)WEXITSTATUS(status)), lean_mk_string("")));
}

LEAN_EXPORT lean_obj_res huh_tty_raw(uint32_t fd) {
  struct termios saved, raw;
  if (tcgetattr((int)fd, &saved) < 0) return io_errno();
  raw = saved;
  cfmakeraw(&raw);
  if (tcsetattr((int)fd, TCSADRAIN, &raw) < 0) return io_errno();
  lean_object *out = lean_alloc_sarray(1, sizeof(saved), sizeof(saved));
  memcpy(lean_sarray_cptr(out), &saved, sizeof(saved));
  return lean_io_result_mk_ok(out);
}

LEAN_EXPORT lean_obj_res huh_tty_restore(uint32_t fd, b_lean_obj_arg saved) {
  struct termios t;
  if (lean_sarray_size(saved) != sizeof(t)) return io_user_error("bad saved terminal state");
  memcpy(&t, lean_sarray_cptr(saved), sizeof(t));
  if (tcsetattr((int)fd, TCSADRAIN, &t) < 0) return io_errno();
  return io_unit();
}

LEAN_EXPORT lean_obj_res huh_tty_winsize(uint32_t fd) {
  struct winsize ws;
  if (ioctl((int)fd, TIOCGWINSZ, &ws) < 0) return io_errno();
  return lean_io_result_mk_ok(pair(lean_box(ws.ws_row), lean_box(ws.ws_col)));
}

LEAN_EXPORT lean_obj_res huh_isatty(uint32_t fd) {
  return lean_io_result_mk_ok(lean_box(isatty((int)fd) ? 1 : 0));
}

/* Set by the handlers huh_read_passphrase installs while echo is off. */
static volatile sig_atomic_t passphrase_signal;

static void passphrase_handler(int sig) { passphrase_signal = sig; }

static void write_all(int fd, const char *s, size_t n) {
  while (n > 0) {
    ssize_t w = write(fd, s, n);
    if (w < 0) { if (errno == EINTR) continue; return; }
    s += w;
    n -= (size_t)w;
  }
}

/* Print `prompt` on /dev/tty and read one line from it with echo off, as readpassphrase(3)
   does. A signal that arrives meanwhile restores the terminal first and is then re-raised, so
   Ctrl-C never leaves echo off. */
LEAN_EXPORT lean_obj_res huh_read_passphrase(b_lean_obj_arg prompt) {
  int fd = open("/dev/tty", O_RDWR | O_NOCTTY | O_CLOEXEC);
  if (fd < 0) return io_user_error("no terminal to read a passphrase from");
  struct termios saved, quiet;
  if (tcgetattr(fd, &saved) < 0) { close(fd); return io_user_error("no terminal to read a passphrase from"); }
  static const int sigs[] = { SIGINT, SIGTERM, SIGHUP, SIGQUIT, SIGTSTP };
  enum { NSIGS = sizeof(sigs) / sizeof(sigs[0]) };
  struct sigaction act, old[NSIGS];
  memset(&act, 0, sizeof(act));
  act.sa_handler = passphrase_handler; /* no SA_RESTART: read must return EINTR */
  sigemptyset(&act.sa_mask);
  passphrase_signal = 0;
  for (int i = 0; i < NSIGS; i++) sigaction(sigs[i], &act, &old[i]);
  quiet = saved;
  quiet.c_lflag &= ~(tcflag_t)(ECHO | ECHONL);
  tcsetattr(fd, TCSAFLUSH, &quiet);
  write_all(fd, lean_string_cstr(prompt), strlen(lean_string_cstr(prompt)));
  char buf[1024];
  size_t len = 0;
  int failed = 0;
  for (;;) {
    /* The handler may run on another of the runtime's threads, leaving this read blocked, so
       wake up now and then to look for a signal. */
    struct pollfd pfd = { .fd = fd, .events = POLLIN };
    int ready = poll(&pfd, 1, 100);
    if (passphrase_signal) break;
    if (ready < 0 && errno == EINTR) continue;
    if (ready == 0) continue;
    char c;
    ssize_t r = read(fd, &c, 1);
    if (r < 0 && errno == EINTR) continue;
    if (r <= 0) { failed = r < 0 || len == 0; break; }
    if (c == '\n' || c == '\r') break;
    if (len < sizeof(buf)) buf[len++] = c;
  }
  tcsetattr(fd, TCSAFLUSH, &saved);
  write_all(fd, "\n", 1);
  close(fd);
  for (int i = 0; i < NSIGS; i++) sigaction(sigs[i], &old[i], NULL);
  if (passphrase_signal) {
    explicit_bzero(buf, sizeof(buf));
    raise(passphrase_signal);
    return io_user_error("interrupted");
  }
  if (failed) { explicit_bzero(buf, sizeof(buf)); return io_user_error("no passphrase read"); }
  lean_object *out = lean_mk_string_from_bytes(buf, len);
  explicit_bzero(buf, sizeof(buf));
  return lean_io_result_mk_ok(out);
}

/* (user name, home, shell) of the effective user. */
LEAN_EXPORT lean_obj_res huh_getpw(void) {
  struct passwd *pw = getpwuid(geteuid());
  if (pw == NULL) return io_user_error("no passwd entry for the current user");
  return lean_io_result_mk_ok(pair(lean_mk_string(pw->pw_name),
      pair(lean_mk_string(pw->pw_dir), lean_mk_string(pw->pw_shell))));
}

/* True when the file is ours and nobody else can read or write it. */
LEAN_EXPORT lean_obj_res huh_file_private(b_lean_obj_arg path) {
  struct stat st;
  if (stat(lean_string_cstr(path), &st) < 0) return io_errno_at(path);
  int ok = st.st_uid == geteuid() && (st.st_mode & 077) == 0;
  return lean_io_result_mk_ok(lean_box(ok ? 1 : 0));
}

LEAN_EXPORT lean_obj_res huh_syslog(uint32_t prio, b_lean_obj_arg msg) {
  static int opened = 0;
  if (!opened) {
    openlog("huhd", LOG_PID, LOG_AUTH);
    opened = 1;
  }
  syslog((int)prio, "%s", lean_string_cstr(msg));
  return io_unit();
}

LEAN_EXPORT lean_obj_res huh_ignore_sigpipe(void) {
  signal(SIGPIPE, SIG_IGN);
  return io_unit();
}
