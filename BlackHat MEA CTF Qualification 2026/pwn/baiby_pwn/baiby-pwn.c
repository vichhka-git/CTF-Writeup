#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

long arr[8];

long getval() {
  char buf[8] = {};
  read(STDIN_FILENO, buf, sizeof(buf)-1);
  return atol(buf);
}

int main() {
  long i, v;
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  setbuf(stderr, NULL);

  while (1) {
    switch (getval()) {
      case 1:
        i = getval();
        v = getval();
        arr[i] = v;
        break;
      case 2:
        memset((void*)arr, 0, sizeof(arr));
        break;
      default:
        return 0;
    }
  }
}
