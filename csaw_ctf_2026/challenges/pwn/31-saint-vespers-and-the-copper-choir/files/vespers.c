/*
 * Saint Vespers and the Copper Choir
 *
 * Beneath the chapel floor, a cathedral machine preserves "holy"
 * recordings in copper coils, replaying them on command. Choristers
 * are recruited, retired to the archive, restored to the loft, and
 * made to sing during the Final Performance.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHOIR       8
#define NAME_SIZE       0x38
#define TRANSCRIPT_MIN  1
#define TRANSCRIPT_MAX  0x1000

typedef struct chorister {
    char   name[NAME_SIZE];
    void (*sing)(struct chorister *self);
    char  *transcript;
    size_t transcript_len;
    int    active;
} chorister_t;

static chorister_t *choir[MAX_CHOIR];

static char g_stdout_buf[0x1000];
static char g_stdin_buf[0x1000];

/* ---------------------------------------------------------------- */
/* raw, stdio-free-ish I/O helpers (buffers above keep stdio itself */
/* from ever touching the heap, so chunk layout stays deterministic) */
/* ---------------------------------------------------------------- */

static void read_exact(char *buf, size_t len) {
    size_t got = 0;
    fflush(stdout);
    while (got < len) {
        ssize_t n = read(0, buf + got, len - got);
        if (n <= 0) exit(0);
        got += (size_t)n;
    }
}

static ssize_t read_line(char *buf, size_t size) {
    size_t got = 0;
    fflush(stdout);
    while (got < size) {
        ssize_t n = read(0, buf + got, 1);
        if (n <= 0) exit(0);
        if (buf[got] == '\n') break;
        got++;
    }
    buf[got] = '\0';
    return (ssize_t)got;
}

static long read_long(void) {
    char tmp[32];
    read_line(tmp, sizeof(tmp) - 1);
    return strtol(tmp, NULL, 10);
}

/* ---------------------------------------------------------------- */
/* hymn styles - a fixed, whitelisted set of callbacks               */
/* ---------------------------------------------------------------- */

static void sing_gregorian(chorister_t *self) {
    printf("  %s intones a slow Gregorian chant.\n", self->name);
}

static void sing_echo(chorister_t *self) {
    printf("  %s sends an echoing round through the nave.\n", self->name);
}

static void sing_harmony(chorister_t *self) {
    printf("  %s weaves a close copper harmony.\n", self->name);
}

static void (*const sing_table[3])(chorister_t *) = {
    sing_gregorian,
    sing_echo,
    sing_harmony,
};

/* ---------------------------------------------------------------- */
/* choir operations                                                  */
/* ---------------------------------------------------------------- */

static int find_empty_slot(void) {
    for (int i = 0; i < MAX_CHOIR; i++)
        if (choir[i] == NULL)
            return i;
    return -1;
}

static void op_recruit(void) {
    int idx = find_empty_slot();
    if (idx < 0) {
        puts("The choir loft is full; no seats remain.");
        return;
    }

    chorister_t *c = malloc(sizeof(chorister_t));
    if (!c) exit(1);
    memset(c, 0, sizeof(*c));

    printf("Name this chorister: ");
    read_line(c->name, NAME_SIZE - 1);

    printf("Choose a hymn style (0=Gregorian, 1=Echo, 2=Harmony): ");
    long style = read_long();
    if (style < 0 || style > 2) style = 0;
    c->sing = sing_table[style];

    printf("Transcript length (%d-%d): ", TRANSCRIPT_MIN, TRANSCRIPT_MAX);
    long len = read_long();
    if (len < TRANSCRIPT_MIN || len > TRANSCRIPT_MAX) {
        puts("The copper coils cannot hold a transcript of that length.");
        free(c);
        return;
    }

    char *transcript = malloc((size_t)len);
    if (!transcript) exit(1);

    printf("Recite the transcript to inscribe (%ld raw bytes): ", len);
    read_exact(transcript, (size_t)len);

    c->transcript = transcript;
    c->transcript_len = (size_t)len;
    c->active = 1;

    choir[idx] = c;
    printf("Chorister seated at position %d.\n", idx);
}

static int valid_idx(long idx) {
    return idx >= 0 && idx < MAX_CHOIR && choir[idx] != NULL;
}

static void op_retire(void) {
    printf("Retire which seat? ");
    long idx = read_long();
    if (!valid_idx(idx)) { puts("No chorister sits there."); return; }

    chorister_t *c = choir[idx];
    if (!c->active) { puts("That chorister is already in the archive."); return; }

    if (c->transcript) free(c->transcript);
    free(c);
    c->active = 0;

    printf("Seat %ld retired to the archive.\n", idx);
}

static void op_restore(void) {
    printf("Restore which seat? ");
    long idx = read_long();
    if (!valid_idx(idx)) { puts("No chorister sits there."); return; }

    chorister_t *c = choir[idx];
    if (c->active) { puts("That chorister is already singing."); return; }

    c->active = 1;
    printf("Seat %ld restored to the loft.\n", idx);
}

static void op_inscribe(void) {
    printf("Inscribe which seat? ");
    long idx = read_long();
    if (!valid_idx(idx)) { puts("No chorister sits there."); return; }

    chorister_t *c = choir[idx];
    if (!c->active) { puts("That chorister is not present to be inscribed."); return; }

    printf("Recite %zu raw bytes to inscribe: ", c->transcript_len);
    read_exact(c->transcript, c->transcript_len);
    puts("The transcript has been inscribed.");
}

static void op_recite(void) {
    printf("Recite which seat? ");
    long idx = read_long();
    if (!valid_idx(idx)) { puts("No chorister sits there."); return; }

    chorister_t *c = choir[idx];
    if (!c->active) { puts("That chorister is not present to recite."); return; }

    printf("Transcript (%zu bytes):\n", c->transcript_len);
    fflush(stdout);
    (void)write(1, c->transcript, c->transcript_len);
    (void)write(1, "\n", 1);
}

static void op_rename(void) {
    printf("Rename which seat? ");
    long idx = read_long();
    if (!valid_idx(idx)) { puts("No chorister sits there."); return; }

    chorister_t *c = choir[idx];
    if (!c->active) { puts("That chorister is not present to be renamed."); return; }

    printf("New name (%d raw bytes): ", NAME_SIZE - 1);
    read_exact(c->name, NAME_SIZE - 1);
    c->name[NAME_SIZE - 1] = '\0';
    puts("The ledger has been corrected.");
}

static void op_roster(void) {
    puts("--- Choir Ledger ---");
    for (int i = 0; i < MAX_CHOIR; i++) {
        if (!choir[i]) continue;
        printf("Seat %d [%s]: ", i, choir[i]->active ? "active" : "archived");
        fflush(stdout);
        (void)write(1, choir[i]->name, NAME_SIZE);
        (void)write(1, "\n", 1);
    }
}

static void op_perform(void) {
    puts("=== The Final Performance begins ===");
    for (int i = 0; i < MAX_CHOIR; i++) {
        if (choir[i] && choir[i]->active)
            choir[i]->sing(choir[i]);
    }
    puts("=== The choir falls silent ===");
}

/* ---------------------------------------------------------------- */

static void print_menu(void) {
    puts("");
    puts("      +===================================+");
    puts("      |  Saint Vespers & the Copper Choir  |");
    puts("      +===================================+");
    puts("  1) Recruit a chorister");
    puts("  2) Retire a chorister to the archive");
    puts("  3) Restore a chorister from the archive");
    puts("  4) Inscribe a transcript");
    puts("  5) Recite a transcript");
    puts("  6) Rename a chorister");
    puts("  7) View the choir ledger");
    puts("  8) Begin the Final Performance");
    puts("  9) Leave the chapel");
    printf("> ");
}

int main(void) {
    setvbuf(stdout, g_stdout_buf, _IOFBF, sizeof(g_stdout_buf));
    setvbuf(stdin, g_stdin_buf, _IOFBF, sizeof(g_stdin_buf));

    puts("The copper coils hum as you descend beneath the chapel floor.");

    while (1) {
        print_menu();
        long choice = read_long();
        switch (choice) {
            case 1: op_recruit();  break;
            case 2: op_retire();   break;
            case 3: op_restore();  break;
            case 4: op_inscribe(); break;
            case 5: op_recite();   break;
            case 6: op_rename();   break;
            case 7: op_roster();   break;
            case 8: op_perform();  break;
            case 9: puts("The chapel door closes behind you."); exit(0);
            default: puts("The sexton does not understand.");
        }
    }
}
