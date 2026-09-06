#define _GNU_SOURCE

#include <fcntl.h>
#include <linux/landlock.h>
#include <stdio.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

extern char **environ;

static const char chal_path[] = "/app/baiby-pwn";
static const char loader_path[] = "/lib64/ld-linux-x86-64.so.2";

static void die(const char *msg) {
  perror(msg);
  _exit(1);
}

static void allow_exec(int ruleset_fd, const char *path) {
  int fd = open(path, O_PATH | O_CLOEXEC);
  if (fd < 0) {
    die(path);
  }

  struct landlock_path_beneath_attr rule = {
      .allowed_access = LANDLOCK_ACCESS_FS_EXECUTE,
      .parent_fd = fd,
  };

  if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
              &rule, 0) < 0) {
    die("landlock_add_rule");
  }

  close(fd);
}

int main(int argc, char **argv) {
  (void)argc;

  struct landlock_ruleset_attr ruleset = {
      .handled_access_fs = LANDLOCK_ACCESS_FS_EXECUTE,
  };

  int ruleset_fd =
      syscall(SYS_landlock_create_ruleset, &ruleset, sizeof(ruleset), 0);
  if (ruleset_fd < 0) {
    die("landlock_create_ruleset");
  }

  allow_exec(ruleset_fd, chal_path);
  allow_exec(ruleset_fd, loader_path);

  if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
    die("prctl(PR_SET_NO_NEW_PRIVS)");
  }

  if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
    die("landlock_restrict_self");
  }

  close(ruleset_fd);

  argv[0] = (char *)chal_path;
  execve(chal_path, argv, environ);
  die("execve");
}
