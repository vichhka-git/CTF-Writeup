#define _GNU_SOURCE
#include <sys/select.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define ERR (-1)
#define KEY_LEFT  1001
#define KEY_RIGHT 1002
#define KEY_UP    1003
#define KEY_DOWN  1004

#define WIDTH   10u
#define HEIGHT  20u
#define VIEW_COLS 80u
#define VIEW_ROWS 20u
#define VIEW_READ_BYTES 4096u
#define FALL_USEC 500000LL
#define INPUT_POLL_USEC 40000

#define ROW_BYTES            ((WIDTH + 7u) / 8u)
#define STAGE_BYTES          (HEIGHT * ROW_BYTES)

#define PIECE_KINDS 7
#define PIECE_ROTS  4
#define PIECE_SIDE  4

enum {
    PIECE_I = 0,
    PIECE_O = 1,
    PIECE_T = 2,
    PIECE_S = 3,
    PIECE_Z = 4,
    PIECE_J = 5,
    PIECE_L = 6,
};

enum {
    MOVE_BLOCKED = 0,
    MOVE_OK = 1,
    MOVE_LOCK = 2,
};

typedef struct {
    char cell[PIECE_SIDE * PIECE_SIDE];
} PieceDef;

static PieceDef pieces[PIECE_KINDS][PIECE_ROTS];
static int ceiling_pressure;

typedef struct {
    uint32_t score;
    uint16_t height;
    uint16_t width;
    uint8_t stage[STAGE_BYTES];
} Game;

typedef struct {
    int kind;
    int rot;
    int x;
    int y;
} Piece;

typedef struct {
    int dx;
    int dy;
} Kick;

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

static void set_pattern(PieceDef *p, const char *s) {
    memcpy(p->cell, s, PIECE_SIDE * PIECE_SIDE);
}

static void init_pieces(void) {
    memset(pieces, 0, sizeof(pieces));

    set_pattern(&pieces[PIECE_I][0], "####............");
    set_pattern(&pieces[PIECE_I][1], ".#...#...#...#..");
    set_pattern(&pieces[PIECE_I][2], "####............");
    set_pattern(&pieces[PIECE_I][3], ".#...#...#...#..");

    for (int r = 0; r < 4; r++)
        set_pattern(&pieces[PIECE_O][r], "##..##..........");

    set_pattern(&pieces[PIECE_T][0], ".#..###.........");
    set_pattern(&pieces[PIECE_T][1], "#...##..#.......");
    set_pattern(&pieces[PIECE_T][2], "###..#..........");
    set_pattern(&pieces[PIECE_T][3], ".#..##...#......");

    set_pattern(&pieces[PIECE_S][0], ".##.##..........");
    set_pattern(&pieces[PIECE_S][1], "#...##...#......");
    set_pattern(&pieces[PIECE_S][2], ".##.##..........");
    set_pattern(&pieces[PIECE_S][3], "#...##...#......");

    set_pattern(&pieces[PIECE_Z][0], "##...##.........");
    set_pattern(&pieces[PIECE_Z][1], ".#..##..#.......");
    set_pattern(&pieces[PIECE_Z][2], "##...##.........");
    set_pattern(&pieces[PIECE_Z][3], ".#..##..#.......");

    set_pattern(&pieces[PIECE_J][0], "#...###.........");
    set_pattern(&pieces[PIECE_J][1], "##..#...#.......");
    set_pattern(&pieces[PIECE_J][2], "###...#.........");
    set_pattern(&pieces[PIECE_J][3], ".#...#..##......");

    set_pattern(&pieces[PIECE_L][0], "..#.###.........");
    set_pattern(&pieces[PIECE_L][1], "#...#...##......");
    set_pattern(&pieces[PIECE_L][2], "###.#...........");
    set_pattern(&pieces[PIECE_L][3], "##...#...#......");
}

static const PieceDef *piece_def(int kind, int rot) {
    return &pieces[kind % PIECE_KINDS][rot & 3];
}

static int piece_occupied(const PieceDef *d, int x, int y) {
    if (x < 0 || x >= PIECE_SIDE || y < 0 || y >= PIECE_SIDE) return 0;
    return d->cell[y * PIECE_SIDE + x] == '#';
}

static int piece_width(const PieceDef *d) {
    int max_x = -1;
    for (int y = 0; y < PIECE_SIDE; y++) {
        for (int x = 0; x < PIECE_SIDE; x++) {
            if (piece_occupied(d, x, y) && x > max_x) max_x = x;
        }
    }
    return max_x >= 0 ? max_x + 1 : 1;
}

static int piece_tall(const PieceDef *d) {
    for (int x = 0; x < PIECE_SIDE; x++) {
        if (piece_occupied(d, x, PIECE_SIDE - 1)) return 1;
    }
    return 0;
}

static size_t stride_bytes(const Game *g) {
    return ((size_t)g->width + 7u) / 8u;
}

static int stage_cell(const Game *g, int x, int y) {
    if (x < 0 || x >= (int)WIDTH || y < 0 || y >= (int)HEIGHT) return 0;
    size_t idx = (size_t)y * ROW_BYTES + (size_t)(x >> 3);
    return (g->stage[idx] >> (x & 7)) & 1;
}

static int get_cell(const Game *g, int x, int y) {
    if (x < 0 || y < 0) return 0;
    if ((uint32_t)x >= g->width || (uint32_t)y >= g->height) return 0;
    size_t idx = (size_t)y * stride_bytes(g) + (size_t)(x >> 3);
    return (g->stage[idx] >> (x & 7)) & 1;
}

static void set_cell(Game *g, int x, int y) {
    if (x < 0) return;
    if (y < -1) return;
    if ((uint32_t)x >= g->width) return;
    if (y >= (int)g->height) return;

    int stride = (int)ROW_BYTES;
    int idx = y * stride + (x >> 3);
    g->stage[idx] |= (uint8_t)(1u << (x & 7));
}

static void game_init(Game *g) {
    memset(g, 0, sizeof(*g));
    g->score = 0;
    g->width = (uint16_t)WIDTH;
    g->height = (uint16_t)HEIGHT;
    ceiling_pressure = 0;
}

static int top_pressure(const Game *g) {
    int occupied = 0;
    for (int y = 0; y < (int)HEIGHT; y++) {
        for (int x = 0; x < (int)WIDTH; x++) {
            size_t idx = (size_t)y * ROW_BYTES + (size_t)(x >> 3);
            occupied += (g->stage[idx] >> (x & 7)) & 1;
        }
    }
    if (occupied >= 60) ceiling_pressure = 1;
    return ceiling_pressure;
}

static int collides(const Game *g, const Piece *p, int nx, int ny, int nrot) {
    const PieceDef *d = piece_def(p->kind, nrot);
    for (int yy = 0; yy < PIECE_SIDE; yy++) {
        for (int xx = 0; xx < PIECE_SIDE; xx++) {
            if (!piece_occupied(d, xx, yy)) continue;
            int x = nx + xx;
            int y = ny + yy;
            if (x < 0) return 1;
            if (y < 0) {
                if ((uint32_t)x >= g->width) return 1;
            } else if (x >= (int)WIDTH) {
                return 1;
            }
            if (y >= (int)HEIGHT) return 1;
            if (y >= 0 && stage_cell(g, x, y)) return 1;
        }
    }
    return 0;
}

static void lock_piece(Game *g, const Piece *p) {
    const PieceDef *d = piece_def(p->kind, p->rot);
    for (int yy = 0; yy < PIECE_SIDE; yy++) {
        for (int xx = 0; xx < PIECE_SIDE; xx++) {
            if (!piece_occupied(d, xx, yy)) continue;
            set_cell(g, p->x + xx, p->y + yy);
        }
    }
}

static int row_full(const Game *g, int y) {
    if (y < 0 || y >= (int)HEIGHT) return 0;
    for (int x = 0; x < (int)WIDTH; x++) {
        if (!stage_cell(g, x, y)) return 0;
    }
    return 1;
}

static void clear_row(Game *g, int y) {
    if (y < 0 || y >= (int)HEIGHT) return;
    size_t stride = stride_bytes(g);
    uint8_t *base = g->stage;
    memmove(base + stride, base, (size_t)y * stride);
    memset(base, 0, stride);
}

static void clear_lines(Game *g) {
    int cleared = 0;
    for (int y = 0; y < (int)HEIGHT; y++) {
        if (row_full(g, y)) {
            clear_row(g, y);
            cleared++;
        }
    }
    if (cleared) g->score += (uint32_t)(cleared * cleared * 100);
}

static int next_kind(void) {
    return rand() % PIECE_KINDS;
}

static void spawn_piece(Piece *p) {
    p->kind = next_kind();
    p->rot = 0;
    const PieceDef *d = piece_def(p->kind, p->rot);
    int w = piece_width(d);

    p->x = (int)WIDTH / 2 - w / 2;
    if (p->x < 0) p->x = 0;
    p->y = -2;
}

static int move_piece(const Game *g, Piece *p, int dx) {
    if (!collides(g, p, p->x + dx, p->y, p->rot)) {
        p->x += dx;
        return 1;
    }
    return 0;
}

static int rotate_piece(Game *g, Piece *p) {
    int nr = (p->rot + 1) & 3;
    const PieceDef *d = piece_def(p->kind, nr);
    static const Kick kicks[] = {
        {0, 0}, {-1, 0}, {1, 0}, {0, -1}, {-1, -1}, {1, -1},
    };
    static const Kick tall_entry_kicks[] = {
        {0, -2}, {-1, -2}, {1, -2}, {0, 0}, {-1, 0}, {1, 0},
    };

    const Kick *table = kicks;
    size_t n = sizeof(kicks) / sizeof(kicks[0]);
    int entry_kick = p->y < 0 && piece_tall(d) && top_pressure(g);
    if (entry_kick) {
        table = tall_entry_kicks;
        n = sizeof(tall_entry_kicks) / sizeof(tall_entry_kicks[0]);
    }

    for (size_t i = 0; i < n; i++) {
        int nx = p->x + table[i].dx;
        int ny = p->y + table[i].dy;
        if (collides(g, p, nx, ny, nr)) continue;
        p->x = nx;
        p->y = ny;
        p->rot = nr;
        if (entry_kick && table[i].dy < 0) return MOVE_LOCK;
        return MOVE_OK;
    }
    return MOVE_BLOCKED;
}

static int step_down_or_lock(Game *g, Piece *p) {
    if (collides(g, p, p->x, p->y, p->rot)) return -1;
    if (!collides(g, p, p->x, p->y + 1, p->rot)) {
        p->y++;
        return 0;
    }
    if (p->y < 0) return -1;
    lock_piece(g, p);
    clear_lines(g);
    return 1;
}

static int hard_drop(Game *g, Piece *p) {
    if (collides(g, p, p->x, p->y, p->rot)) return -1;
    while (p->y + 1 < (int)HEIGHT && !collides(g, p, p->x, p->y + 1, p->rot)) p->y++;
    if (p->y < 0) return -1;
    lock_piece(g, p);
    clear_lines(g);
    return 1;
}

static void lock_spawn_next(Piece *p) {
    spawn_piece(p);
}

static void render_piece_overlay(char *line, uint32_t line_width, const Piece *p, int y) {
    const PieceDef *d = piece_def(p->kind, p->rot);
    for (int yy = 0; yy < PIECE_SIDE; yy++) {
        for (int xx = 0; xx < PIECE_SIDE; xx++) {
            if (!piece_occupied(d, xx, yy)) continue;
            int px = p->x + xx;
            int py = p->y + yy;
            if (py == y && px >= 0 && (uint32_t)px < line_width) {
                line[(uint32_t)px] = '@';
            }
        }
    }
}

static void draw_live(const Game *g, const Piece *p) {
    printf("\033[H\033[2J");

    uint32_t usable_cols = VIEW_COLS;
    if (usable_cols > g->width) usable_cols = g->width;

    char *line = malloc((size_t)usable_cols + 1);
    if (!line) die("malloc");

    for (int row = 0; row < (int)VIEW_ROWS; row++) {
        int y = row;
        if (y >= (int)g->height) break;
        int readable = (size_t)y * stride_bytes(g) < VIEW_READ_BYTES;
        for (uint32_t i = 0; i < usable_cols; i++) {
            line[i] = readable && get_cell(g, (int)i, y) ? '#' : '.';
        }
        line[usable_cols] = '\0';
        render_piece_overlay(line, usable_cols, p, y);
        printf("|%s|\n", line);
    }
    free(line);
    fflush(stdout);
}

static inline void terminal_start(void) {
    printf("\033[?25l\033[2J\033[H");
}

static inline void terminal_stop(void) {
    printf("\033[?25h\033[0m\n");
}

static int64_t now_usec(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) die("clock_gettime");
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

static int read_byte_with_timeout(int timeout_us) {
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(STDIN_FILENO, &rfds);
    struct timeval tv;
    tv.tv_sec = timeout_us / 1000000;
    tv.tv_usec = timeout_us % 1000000;
    int r = select(STDIN_FILENO + 1, &rfds, NULL, NULL, &tv);
    if (r <= 0) return ERR;
    unsigned char c;
    if (read(STDIN_FILENO, &c, 1) != 1) return ERR;
    return c;
}

static int live_getch_timeout(int timeout_us) {
    int c = read_byte_with_timeout(timeout_us);
    if (c != 0x1b) return c;

    int b1 = read_byte_with_timeout(1000);
    int b2 = read_byte_with_timeout(1000);
    if (b1 == '[') {
        if (b2 == 'A') return KEY_UP;
        if (b2 == 'B') return KEY_DOWN;
        if (b2 == 'C') return KEY_RIGHT;
        if (b2 == 'D') return KEY_LEFT;
    }
    return 0x1b;
}

static int handle_live_key(Game *g, Piece *p, int ch) {
    int locked = 0;
    int topout = 0;

    switch (ch) {
        case ERR: return 0;
        case 'a': case KEY_LEFT: move_piece(g, p, -1); break;
        case 'd': case KEY_RIGHT: move_piece(g, p, +1); break;
        case 's': case KEY_DOWN: {
            int r = step_down_or_lock(g, p);
            topout = r < 0;
            locked = r > 0;
            break;
        }
        case 'w': case KEY_UP:
            if (rotate_piece(g, p) == MOVE_LOCK) {
                lock_piece(g, p);
                locked = 1;
            }
            break;
        case '.': case ' ':
            topout = hard_drop(g, p) < 0;
            locked = !topout;
            break;
        default:
            break;
    }

    if (topout) return -1;
    if (locked) {
        lock_spawn_next(p);
        return 1;
    }
    return 0;
}

static void play_session_live(void) {
    Game game;
    Piece active;
    int round_over = 0;

    game_init(&game);
    terminal_start();
    spawn_piece(&active);
    draw_live(&game, &active);
    int64_t next_fall = now_usec() + FALL_USEC;

    while (!round_over) {
        int changed = 0;
        int64_t now = now_usec();
        int timeout_us = 0;
        if (now < next_fall) {
            int64_t remain = next_fall - now;
            timeout_us = remain > INPUT_POLL_USEC ? INPUT_POLL_USEC : (int)remain;
        }

        int ch = live_getch_timeout(timeout_us);
        while (ch != ERR) {
            int r = handle_live_key(&game, &active, ch);
            changed = 1;
            if (r < 0) {
                round_over = 1;
                break;
            }
            if (r > 0) next_fall = now_usec() + FALL_USEC;
            ch = live_getch_timeout(0);
        }

        if (round_over) break;

        now = now_usec();
        if (now >= next_fall) {
            int r = step_down_or_lock(&game, &active);
            if (r < 0) {
                round_over = 1;
                break;
            }
            if (r > 0) lock_spawn_next(&active);
            changed = 1;
            next_fall = now_usec() + FALL_USEC;
        }

        if (changed) draw_live(&game, &active);
    }

    terminal_stop();
    puts("GAME OVER");
}

int main(void) {
    init_pieces();
    play_session_live();
    return 0;
}
