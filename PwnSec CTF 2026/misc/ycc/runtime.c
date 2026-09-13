#include "runtime.h"
#include <inttypes.h>
#include <sys/wait.h>
#include <unistd.h>
YValue *y_mk_long(long v) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_LONG;
    val->data.l = v;
    return val;
}
YValue *y_mk_float(double v) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_FLOAT;
    val->data.f = v;
    return val;
}
YValue *y_mk_bool(bool v) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_BOOL;
    val->data.b = v;
    return val;
}
YValue *y_mk_str(const char *s) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_STR;
    val->data.s = strdup(s);
    return val;
}
YValue *y_mk_str_n(const char *s, size_t len) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_STR;
    val->data.s = malloc(len + 1);
    memcpy(val->data.s, s, len);
    val->data.s[len] = '\0';
    return val;
}
YValue *y_mk_null(void) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_NULL;
    return val;
}
YValue *y_mk_arr(YValue **elements, size_t count) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_ARR;
    YArray *arr = malloc(sizeof(YArray));
    arr->refcount = 1;
    arr->count = count;
    if (count > 0 && elements) {
        arr->elements = malloc(sizeof(YValue *) * count);
        memcpy(arr->elements, elements, sizeof(YValue *) * count);
    } else {
        arr->elements = NULL;
    }
    val->data.arr = arr;
    return val;
}
YValue *y_mk_map(YMapEntry *entries, size_t count) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_MAP;
    YMap *map = malloc(sizeof(YMap));
    map->refcount = 1;
    if (count > 0 && entries) {
        map->entries = malloc(sizeof(YMapEntry) * count);
        size_t n = 0;
        for (size_t i = 0; i < count; i++) {
            size_t existing = n;
            for (size_t j = 0; j < n; j++) {
                if (strcmp(map->entries[j].key, entries[i].key) == 0) {
                    existing = j;
                    break;
                }
            }
            if (existing < n) {
                y_free(map->entries[existing].value);
                map->entries[existing].value = entries[i].value;
            } else {
                map->entries[n].key = strdup(entries[i].key);
                map->entries[n].value = entries[i].value;
                n++;
            }
        }
        map->count = n;
    } else {
        map->entries = NULL;
        map->count = 0;
    }
    val->data.map = map;
    return val;
}
YValue *y_mk_func(YFuncPtr fn, size_t arity, YScope *closure) {
    YValue *val = malloc(sizeof(YValue));
    val->type = Y_FUNC;
    YFunc *f = malloc(sizeof(YFunc));
    f->fn = fn;
    f->arity = arity;
    f->closure = closure ? y_scope_retain(closure) : NULL;
    val->data.func = f;
    return val;
}
void y_scope_init(YScope *scope, YScope *parent) {
    scope->entries = NULL;
    scope->parent = parent;
    scope->refcount = 1;
}
YScope *y_scope_retain(YScope *scope) {
    if (scope) scope->refcount++;
    return scope;
}
void y_scope_release(YScope *scope) {
    if (!scope) return;
    if (--scope->refcount > 0) return;
    if (scope->refcount < 0) return;
    scope->refcount = -1;
    YScopeEntry *e = scope->entries;
    scope->entries = NULL;
    while (e) {
        YScopeEntry *next = e->next;
        free(e->name);
        y_free(e->value);
        free(e);
        e = next;
    }
    free(scope);
}
YValue *y_scope_get(YScope *scope, const char *name) {
    for (YScope *s = scope; s; s = s->parent) {
        for (YScopeEntry *e = s->entries; e; e = e->next) {
            if (strcmp(e->name, name) == 0) return e->value;
        }
    }
    fprintf(stderr, "runtime error: undefined variable '%s'\n", name);
    exit(1);
}
YValue *y_scope_take(YScope *scope, const char *name) {
    for (YScope *s = scope; s; s = s->parent) {
        for (YScopeEntry *e = s->entries; e; e = e->next) {
            if (strcmp(e->name, name) == 0) {
                YValue *val = e->value;
                e->value = y_mk_null();
                return val;
            }
        }
    }
    return NULL;
}
void y_scope_set(YScope *scope, const char *name, YValue *value) {
    for (YScope *s = scope; s; s = s->parent) {
        for (YScopeEntry *e = s->entries; e; e = e->next) {
            if (strcmp(e->name, name) == 0) {
                y_free(e->value);
                e->value = value;
                return;
            }
        }
    }
    YScopeEntry *e = malloc(sizeof(YScopeEntry));
    e->name = strdup(name);
    e->value = value;
    e->next = scope->entries;
    scope->entries = e;
}
void y_scope_set_local(YScope *scope, const char *name, YValue *value) {
    for (YScopeEntry *e = scope->entries; e; e = e->next) {
        if (strcmp(e->name, name) == 0) {
            y_free(e->value);
            e->value = value;
            return;
        }
    }
    YScopeEntry *e = malloc(sizeof(YScopeEntry));
    e->name = strdup(name);
    e->value = value;
    e->next = scope->entries;
    scope->entries = e;
}
static void y_arr_cow(YValue *arr) {
    if (arr->data.arr->refcount > 1) {
        YArray *old = arr->data.arr;
        YArray *new = malloc(sizeof(YArray));
        new->refcount = 1;
        new->count = old->count;
        new->elements = malloc(sizeof(YValue *) * old->count);
        for (size_t i = 0; i < old->count; i++)
            new->elements[i] = y_clone(old->elements[i]);
        old->refcount--;
        arr->data.arr = new;
    }
}
static void y_map_cow(YValue *map) {
    if (map->data.map->refcount > 1) {
        YMap *old = map->data.map;
        YMap *new = malloc(sizeof(YMap));
        new->refcount = 1;
        new->count = old->count;
        new->entries = malloc(sizeof(YMapEntry) * old->count);
        for (size_t i = 0; i < old->count; i++) {
            new->entries[i].key = strdup(old->entries[i].key);
            new->entries[i].value = y_clone(old->entries[i].value);
        }
        old->refcount--;
        map->data.map = new;
    }
}
YValue *y_clone(YValue *val) {
    if (!val) return y_mk_null();
    switch (val->type) {
    case Y_LONG: return y_mk_long(val->data.l);
    case Y_FLOAT: return y_mk_float(val->data.f);
    case Y_BOOL: return y_mk_bool(val->data.b);
    case Y_STR: return y_mk_str(val->data.s);
    case Y_NULL: return y_mk_null();
    case Y_ARR: {
        YValue *v = malloc(sizeof(YValue));
        v->type = Y_ARR;
        v->data.arr = val->data.arr;
        v->data.arr->refcount++;
        return v;
    }
    case Y_MAP: {
        YValue *v = malloc(sizeof(YValue));
        v->type = Y_MAP;
        v->data.map = val->data.map;
        v->data.map->refcount++;
        return v;
    }
    case Y_FUNC: {
        YValue *v = malloc(sizeof(YValue));
        v->type = Y_FUNC;
        YFunc *f = malloc(sizeof(YFunc));
        f->fn = val->data.func->fn;
        f->arity = val->data.func->arity;
        f->closure = y_scope_retain(val->data.func->closure);
        v->data.func = f;
        return v;
    }
    }
    return y_mk_null();
}
void y_free(YValue *val) {
    if (!val) return;
    switch (val->type) {
    case Y_STR: free(val->data.s); break;
    case Y_ARR:
        if (--val->data.arr->refcount == 0) {
            for (size_t i = 0; i < val->data.arr->count; i++)
                y_free(val->data.arr->elements[i]);
            free(val->data.arr->elements);
            free(val->data.arr);
        }
        break;
    case Y_MAP:
        if (--val->data.map->refcount == 0) {
            for (size_t i = 0; i < val->data.map->count; i++) {
                free(val->data.map->entries[i].key);
                y_free(val->data.map->entries[i].value);
            }
            free(val->data.map->entries);
            free(val->data.map);
        }
        break;
    case Y_FUNC:
        y_scope_release(val->data.func->closure);
        free(val->data.func);
        break;
    default: break;
    }
    free(val);
}
static void y_to_buf(YValue *val, char *buf, size_t sz) {
    if (sz <= 1) return;
    switch (val->type) {
    case Y_LONG: snprintf(buf, sz, "%ld", val->data.l); break;
    case Y_FLOAT: snprintf(buf, sz, "%f", val->data.f); break;
    case Y_BOOL: snprintf(buf, sz, "%s", val->data.b ? "true" : "false"); break;
    case Y_STR: snprintf(buf, sz, "%s", val->data.s); break;
    case Y_NULL: snprintf(buf, sz, "null"); break;
    case Y_ARR: {
        snprintf(buf, sz, "[");
        for (size_t i = 0; i < val->data.arr->count; i++) {
            size_t len = strlen(buf);
            y_to_buf(val->data.arr->elements[i], buf + len, sz - len);
            if (i + 1 < val->data.arr->count)
                strncat(buf, ", ", sz - strlen(buf) - 1);
        }
        strncat(buf, "]", sz - strlen(buf) - 1);
        break;
    }
    case Y_MAP: {
        snprintf(buf, sz, "{");
        for (size_t i = 0; i < val->data.map->count; i++) {
            strncat(buf, val->data.map->entries[i].key,
                    sz - strlen(buf) - 1);
            strncat(buf, ": ", sz - strlen(buf) - 1);
            size_t len = strlen(buf);
            y_to_buf(val->data.map->entries[i].value, buf + len, sz - len);
            if (i + 1 < val->data.map->count)
                strncat(buf, ", ", sz - strlen(buf) - 1);
        }
        strncat(buf, "}", sz - strlen(buf) - 1);
        break;
    }
    case Y_FUNC: snprintf(buf, sz, "<function>"); break;
    }
}
char *y_to_str(YValue *val) {
    if (val && val->type == Y_STR)
        return strdup(val->data.s);
    char *buf = malloc(4096);
    buf[0] = '\0';
    y_to_buf(val, buf, 4096);
    return buf;
}
void y_print(YValue *val) {
    char *s = y_to_str(val);
    printf("%s\n", s);
    free(s);
}
bool y_equals(YValue *a, YValue *b) {
    if (!a || !b) return a == b;
    if (a == b) return true;
    if (a->type != b->type) return false;
    switch (a->type) {
    case Y_LONG: return a->data.l == b->data.l;
    case Y_FLOAT: return a->data.f == b->data.f;
    case Y_BOOL: return a->data.b == b->data.b;
    case Y_STR: return strcmp(a->data.s, b->data.s) == 0;
    case Y_NULL: return true;
    case Y_ARR: {
        if (a->data.arr->count != b->data.arr->count) return false;
        for (size_t i = 0; i < a->data.arr->count; i++)
            if (!y_equals(a->data.arr->elements[i], b->data.arr->elements[i]))
                return false;
        return true;
    }
    case Y_MAP: {
        if (a->data.map->count != b->data.map->count) return false;
        for (size_t i = 0; i < a->data.map->count; i++) {
            YValue *bv = y_map_get(b, a->data.map->entries[i].key);
            if (!bv || !y_equals(a->data.map->entries[i].value, bv))
                return false;
        }
        return true;
    }
    case Y_FUNC: return a->data.func == b->data.func;
    }
    return false;
}
#define NUMERIC_BINOP(name, op)                                                \
    YValue *name(YValue *a, YValue *b) {                                      \
        YValue *_res;                                                         \
        if (a->type == Y_LONG && b->type == Y_LONG)                           \
            _res = y_mk_long(a->data.l op b->data.l);                         \
        else {                                                                \
            double av = a->type == Y_LONG ? (double)a->data.l : a->data.f;    \
            double bv = b->type == Y_LONG ? (double)b->data.l : b->data.f;    \
            _res = y_mk_float(av op bv);                                      \
        }                                                                     \
        y_free(a); y_free(b);                                                 \
        return _res;                                                          \
    }
NUMERIC_BINOP(y_sub, -)
NUMERIC_BINOP(y_mul, *)
YValue *y_add(YValue *a, YValue *b) {
    if (a->type == Y_STR || b->type == Y_STR) {
        char *as = a->type == Y_STR ? a->data.s : y_to_str(a);
        char *bs = b->type == Y_STR ? b->data.s : y_to_str(b);
        size_t len = strlen(as) + strlen(bs) + 1;
        char *result = malloc(len);
        strcpy(result, as);
        strcat(result, bs);
        if (a->type != Y_STR) free(as);
        if (b->type != Y_STR) free(bs);
        y_free(a); y_free(b);
        YValue *v = malloc(sizeof(YValue));
        v->type = Y_STR;
        v->data.s = result;
        return v;
    }
    if (a->type == Y_LONG && b->type == Y_LONG) {
        long r = a->data.l + b->data.l;
        y_free(a); y_free(b);
        return y_mk_long(r);
    }
    double av = a->type == Y_LONG ? (double)a->data.l : a->data.f;
    double bv = b->type == Y_LONG ? (double)b->data.l : b->data.f;
    y_free(a); y_free(b);
    return y_mk_float(av + bv);
}
YValue *y_div(YValue *a, YValue *b) {
    if (a->type == Y_LONG && b->type == Y_LONG) {
        if (b->data.l == 0) {
            fprintf(stderr, "runtime error: division by zero\n");
            exit(1);
        }
        long r = a->data.l / b->data.l;
        y_free(a); y_free(b);
        return y_mk_long(r);
    }
    double av = a->type == Y_LONG ? (double)a->data.l : a->data.f;
    double bv = b->type == Y_LONG ? (double)b->data.l : b->data.f;
    y_free(a); y_free(b);
    return y_mk_float(av / bv);
}
YValue *y_mod(YValue *a, YValue *b) {
    if (a->type != Y_LONG || b->type != Y_LONG) {
        fprintf(stderr, "runtime error: %% requires integer operands\n");
        exit(1);
    }
    if (b->data.l == 0) {
        fprintf(stderr, "runtime error: modulo by zero\n");
        exit(1);
    }
    long r = a->data.l % b->data.l;
    y_free(a); y_free(b);
    return y_mk_long(r);
}
#define CMP_BINOP(name, op)                                                    \
    YValue *name(YValue *a, YValue *b) {                                      \
        bool res;                                                             \
        if (a->type == Y_LONG && b->type == Y_LONG)                           \
            res = a->data.l op b->data.l;                                     \
        else {                                                                \
            double av = a->type == Y_LONG ? (double)a->data.l : a->data.f;    \
            double bv = b->type == Y_LONG ? (double)b->data.l : b->data.f;    \
            res = av op bv;                                                   \
        }                                                                     \
        y_free(a); y_free(b);                                                 \
        return y_mk_bool(res);                                                \
    }
CMP_BINOP(y_lt, <)
CMP_BINOP(y_gt, >)
CMP_BINOP(y_lte, <=)
CMP_BINOP(y_gte, >=)
YValue *y_eq(YValue *a, YValue *b) { bool r = y_equals(a, b); y_free(a); y_free(b); return y_mk_bool(r); }
YValue *y_neq(YValue *a, YValue *b) { bool r = !y_equals(a, b); y_free(a); y_free(b); return y_mk_bool(r); }
YValue *y_and(YValue *a, YValue *b) {
    if (a->type != Y_BOOL || b->type != Y_BOOL) {
        fprintf(stderr, "runtime error: && requires boolean operands\n");
        exit(1);
    }
    bool r = a->data.b && b->data.b;
    y_free(a); y_free(b);
    return y_mk_bool(r);
}
YValue *y_or(YValue *a, YValue *b) {
    if (a->type != Y_BOOL || b->type != Y_BOOL) {
        fprintf(stderr, "runtime error: || requires boolean operands\n");
        exit(1);
    }
    bool r = a->data.b || b->data.b;
    y_free(a); y_free(b);
    return y_mk_bool(r);
}
YValue *y_neg(YValue *a) {
    if (a->type == Y_LONG) { long r = -a->data.l; y_free(a); return y_mk_long(r); }
    double r = -a->data.f; y_free(a); return y_mk_float(r);
}
YValue *y_arr_index(YValue *arr, YValue *idx) {
    if (arr->type != Y_ARR) {
        fprintf(stderr, "runtime error: indexing a non-array\n");
        exit(1);
    }
    long i = idx->data.l;
    long count = (long)arr->data.arr->count;
    if (count == 0) {
        fprintf(stderr, "runtime error: index out of bounds (empty array)\n");
        exit(1);
    }
    i = ((i % count) + count) % count;
    YValue *elem = y_clone(arr->data.arr->elements[i]);
    y_free(idx);
    y_free(arr); 
    return elem;
}
YValue *y_arr_index_borrow(YValue *arr, YValue *idx) {
    if (arr->type != Y_ARR) {
        fprintf(stderr, "runtime error: indexing a non-array\n");
        exit(1);
    }
    long i = idx->data.l;
    long count = (long)arr->data.arr->count;
    if (count == 0) {
        fprintf(stderr, "runtime error: index out of bounds (empty array)\n");
        exit(1);
    }
    i = ((i % count) + count) % count;
    YValue *elem = y_clone(arr->data.arr->elements[i]);
    y_free(idx);
    return elem;
}
YValue *y_arr_slice(YValue *arr, YValue *start_v, YValue *end_v) {
    if (arr->type != Y_ARR) {
        fprintf(stderr, "runtime error: slicing a non-array\n");
        exit(1);
    }
    long count = (long)arr->data.arr->count;
    if (count == 0) {
        return y_mk_arr(NULL, 0);
    }
    long start = start_v->data.l;
    long end = end_v->data.l;
    if (count <= 1 && start >= 1) {
        return y_mk_arr(NULL, 0);
    }
    start = ((start % count) + count) % count;
    end = ((end % count) + count) % count;
    bool reversed = false;
    if (end < start) {
        reversed = true;
        long tmp = start;
        start = end;
        end = tmp;
    }
    size_t n = (size_t)(end - start + 1);
    YValue **elems = malloc(sizeof(YValue *) * n);
    for (size_t i = 0; i < n; i++) {
        long idx = (start + (long)i) % count;
        elems[i] = y_clone(arr->data.arr->elements[idx]);
    }
    if (reversed) {
        for (size_t i = 0; i < n / 2; i++) {
            YValue *tmp = elems[i];
            elems[i] = elems[n - 1 - i];
            elems[n - 1 - i] = tmp;
        }
    }
    return y_mk_arr(elems, n);
}
YValue *y_map_get(YValue *map, const char *key) {
    if (map->type != Y_MAP) return NULL;
    for (size_t i = 0; i < map->data.map->count; i++) {
        if (strcmp(map->data.map->entries[i].key, key) == 0)
            return map->data.map->entries[i].value;
    }
    return NULL;
}
YValue *y_builtin_map_set(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 3 || args[0]->type != Y_MAP || args[1]->type != Y_STR)
        return argc >= 1 ? args[0] : y_mk_null();
    YValue *map = args[0];
    const char *key = args[1]->data.s;
    y_map_cow(map);
    YMap *m = map->data.map;
    for (size_t i = 0; i < m->count; i++) {
        if (strcmp(m->entries[i].key, key) == 0) {
            y_free(m->entries[i].value);
            m->entries[i].value = y_clone(args[2]);
            return map;
        }
    }
    m->entries = realloc(m->entries, sizeof(YMapEntry) * (m->count + 1));
    m->entries[m->count].key = strdup(key);
    m->entries[m->count].value = y_clone(args[2]);
    m->count++;
    return map;
}
YValue *y_builtin_map_get(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_MAP || args[1]->type != Y_STR)
        return y_mk_null();
    YValue *v = y_map_get(args[0], args[1]->data.s);
    return v ? y_clone(v) : y_mk_null();
}
YValue *y_builtin_global_get(YScope *closure, YValue **args, size_t argc) {
    if (argc < 1 || args[0]->type != Y_STR) return y_mk_null();
    const char *name = args[0]->data.s;
    for (YScope *s = closure; s; s = s->parent) {
        for (YScopeEntry *e = s->entries; e; e = e->next) {
            if (strcmp(e->name, name) == 0) return y_clone(e->value);
        }
    }
    return y_mk_null();
}
static YScope **g_vm_scopes = NULL;
static size_t g_vm_scope_count = 0;
static size_t g_vm_scope_cap = 0;
YValue *y_builtin_scope_new(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    long parent_id = (argc >= 1 && args[0]->type == Y_LONG) ? args[0]->data.l : -1;
    if (g_vm_scope_count >= g_vm_scope_cap) {
        g_vm_scope_cap = g_vm_scope_cap ? g_vm_scope_cap * 2 : 16;
        g_vm_scopes = realloc(g_vm_scopes, sizeof(YScope *) * g_vm_scope_cap);
    }
    YScope *s = malloc(sizeof(YScope));
    YScope *parent = (parent_id >= 0 && (size_t)parent_id < g_vm_scope_count)
                         ? g_vm_scopes[parent_id] : NULL;
    y_scope_init(s, parent);
    long id = (long)g_vm_scope_count++;
    g_vm_scopes[id] = s;
    return y_mk_long(id);
}
YValue *y_builtin_scope_def(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 3 || args[0]->type != Y_LONG || args[1]->type != Y_STR) return y_mk_null();
    long id = args[0]->data.l;
    if (id < 0 || (size_t)id >= g_vm_scope_count) return y_mk_null();
    y_scope_set(g_vm_scopes[id], args[1]->data.s, y_clone(args[2]));
    return y_mk_null();
}
YValue *y_builtin_scope_find(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_LONG || args[1]->type != Y_STR) return y_mk_long(-1);
    long id = args[0]->data.l;
    const char *name = args[1]->data.s;
    while (id >= 0 && (size_t)id < g_vm_scope_count) {
        YScope *s = g_vm_scopes[id];
        for (YScopeEntry *e = s->entries; e; e = e->next) {
            if (strcmp(e->name, name) == 0) return y_mk_long(id);
        }
        long pid = -1;
        for (size_t i = 0; i < g_vm_scope_count; i++) {
            if (g_vm_scopes[i] == s->parent) { pid = (long)i; break; }
        }
        id = pid;
    }
    return y_mk_long(-1);
}
YValue *y_builtin_scope_get(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_LONG || args[1]->type != Y_STR) return y_mk_null();
    YValue *find_args[2] = { args[0], args[1] };
    YValue *found = y_builtin_scope_find(closure, find_args, 2);
    if (found->data.l < 0) { y_free(found); return y_mk_null(); }
    long sid = found->data.l;
    y_free(found);
    YValue *v = y_scope_get(g_vm_scopes[sid], args[1]->data.s);
    return v ? y_clone(v) : y_mk_null();
}
YValue *y_builtin_scope_set(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 3 || args[0]->type != Y_LONG || args[1]->type != Y_STR) return y_mk_null();
    YValue *find_args[2] = { args[0], args[1] };
    YValue *found = y_builtin_scope_find(closure, find_args, 2);
    long sid = found->data.l;
    y_free(found);
    if (sid < 0) sid = args[0]->data.l;
    if (sid < 0 || (size_t)sid >= g_vm_scope_count) return y_mk_null();
    y_scope_set(g_vm_scopes[sid], args[1]->data.s, y_clone(args[2]));
    return y_mk_null();
}
YValue *y_cons(YValue *head, YValue *tail) {
    if (tail->type != Y_ARR) {
        fprintf(stderr, "runtime error: :: requires array on right\n");
        exit(1);
    }
    size_t n = tail->data.arr->count + 1;
    YValue **elems = malloc(sizeof(YValue *) * n);
    elems[0] = y_clone(head);
    for (size_t i = 0; i < tail->data.arr->count; i++)
        elems[i + 1] = y_clone(tail->data.arr->elements[i]);
    return y_mk_arr(elems, n);
}
YValue *y_call(YValue *callee, YValue **args, size_t argc) {
    if (callee->type != Y_FUNC) {
        fprintf(stderr, "runtime error: calling a non-function\n");
        exit(1);
    }
    return callee->data.func->fn(callee->data.func->closure, args, argc);
}
YValue *y_builtin_print(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc > 0) y_print(args[0]);
    return y_mk_null();
}
YValue *y_builtin_tostring(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc > 0) {
        char *s = y_to_str(args[0]);
        YValue *v = malloc(sizeof(YValue));
        v->type = Y_STR;
        v->data.s = s;
        return v;
    }
    return y_mk_null();
}
YValue *y_builtin_range(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_LONG) {
        fprintf(stderr, "runtime error: range() requires a long argument\n");
        exit(1);
    }
    long n = args[0]->data.l;
    if (n < 0) n = 0;
    YValue **elems = malloc(sizeof(YValue *) * (size_t)n);
    for (long i = 0; i < n; i++) elems[i] = y_mk_long(i);
    return y_mk_arr(elems, (size_t)n);
}
static void y_type_name(YValue *val, char *buf, size_t sz) {
    switch (val->type) {
    case Y_LONG: snprintf(buf, sz, "long"); break;
    case Y_FLOAT: snprintf(buf, sz, "float"); break;
    case Y_BOOL: snprintf(buf, sz, "bool"); break;
    case Y_STR: snprintf(buf, sz, "str"); break;
    case Y_NULL: snprintf(buf, sz, "null"); break;
    case Y_ARR:
        snprintf(buf, sz, "[");
        if (val->data.arr->count > 0) {
            size_t len = strlen(buf);
            y_type_name(val->data.arr->elements[0], buf + len, sz - len);
        }
        strncat(buf, "]", sz - strlen(buf) - 1);
        break;
    case Y_MAP:
        snprintf(buf, sz, "{");
        for (size_t i = 0; i < val->data.map->count; i++) {
            strncat(buf, val->data.map->entries[i].key, sz - strlen(buf) - 1);
            strncat(buf, ": ", sz - strlen(buf) - 1);
            size_t len = strlen(buf);
            y_type_name(val->data.map->entries[i].value, buf + len, sz - len);
            if (i + 1 < val->data.map->count)
                strncat(buf, ", ", sz - strlen(buf) - 1);
        }
        strncat(buf, "}", sz - strlen(buf) - 1);
        break;
    case Y_FUNC: {
        snprintf(buf, sz, "(");
        for (size_t i = 0; i < val->data.func->arity; i++) {
            strncat(buf, "<inferred>", sz - strlen(buf) - 1);
            if (i + 1 < val->data.func->arity)
                strncat(buf, ", ", sz - strlen(buf) - 1);
        }
        strncat(buf, ")-><inferred>", sz - strlen(buf) - 1);
        break;
    }
    }
}
YValue *y_builtin_typeof(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1) return y_mk_null();
    char buf[512];
    y_type_name(args[0], buf, sizeof(buf));
    YValue *v = malloc(sizeof(YValue));
    v->type = Y_STR;
    v->data.s = strdup(buf);
    return v;
}
YValue *y_builtin_readline(YScope *closure, YValue **args, size_t argc) {
    (void)closure; (void)args; (void)argc;
    char *line = NULL;
    size_t cap = 0;
    ssize_t n = getline(&line, &cap, stdin);
    if (n < 0) { free(line); return y_mk_null(); }
    if (n > 0 && line[n - 1] == '\n') line[--n] = '\0';
    YValue *v = malloc(sizeof(YValue));
    v->type = Y_STR;
    v->data.s = line;
    return v;
}
YValue *y_builtin_clear_eof(YScope *closure, YValue **args, size_t argc) {
    (void)closure; (void)args; (void)argc;
    clearerr(stdin);
    return y_mk_null();
}
YValue *y_builtin_puts(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc > 0) {
        char *s = y_to_str(args[0]);
        fputs(s, stdout);
        fflush(stdout);
        free(s);
    }
    return y_mk_null();
}
YValue *y_builtin_split(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_STR || args[1]->type != Y_STR)
        return y_mk_arr(NULL, 0);
    const char *s = args[0]->data.s;
    const char *delim = args[1]->data.s;
    size_t dlen = strlen(delim);
    if (dlen == 0) return y_mk_arr(NULL, 0);
    size_t count = 0;
    const char *p = s;
    while (*p) {
        count++;
        const char *next = strstr(p, delim);
        p = next ? next + dlen : p + strlen(p);
    }
    if (count == 0) return y_mk_arr(NULL, 0);
    YValue **elems = malloc(sizeof(YValue *) * count);
    size_t i = 0;
    p = s;
    while (*p) {
        const char *next = strstr(p, delim);
        size_t len = next ? (size_t)(next - p) : strlen(p);
        elems[i++] = y_mk_str_n(p, len);
        p = next ? next + dlen : p + strlen(p);
    }
    YValue *arr = y_mk_arr(elems, count);
    free(elems);
    return arr;
}
YValue *y_builtin_len(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1) return y_mk_long(0);
    switch (args[0]->type) {
    case Y_STR: return y_mk_long((long)strlen(args[0]->data.s));
    case Y_ARR: return y_mk_long((long)args[0]->data.arr->count);
    default: return y_mk_long(0);
    }
}
YValue *y_builtin_trim(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR) return y_mk_str("");
    const char *s = args[0]->data.s;
    while (*s == ' ' || *s == '\t' || *s == '\n' || *s == '\r') s++;
    size_t len = strlen(s);
    while (len > 0 && (s[len-1] == ' ' || s[len-1] == '\t' ||
                       s[len-1] == '\n' || s[len-1] == '\r'))
        len--;
    return y_mk_str_n(s, len);
}
YValue *y_builtin_exec(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR) return y_mk_long(-1);
    int ret = system(args[0]->data.s);
    return y_mk_long(WIFEXITED(ret) ? WEXITSTATUS(ret) : -1);
}
YValue *y_builtin_spawn(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR) return y_mk_long(-1);
    char *buf = strdup(args[0]->data.s);
    size_t max = strlen(buf) / 2 + 4;
    char **av = malloc(sizeof(char *) * max);
    int ac = 0;
    char *save = NULL;
    for (char *t = strtok_r(buf, " \t", &save); t != NULL; t = strtok_r(NULL, " \t", &save)) {
        av[ac++] = t;
    }
    av[ac] = NULL;
    if (ac == 0) { free(buf); free(av); return y_mk_long(0); }
    pid_t pid = fork();
    if (pid < 0) { free(buf); free(av); return y_mk_long(-1); }
    if (pid == 0) {
        int i = 0;
        while (i < ac) {
            char *eq = strchr(av[i], '=');
            if (eq != NULL && eq != av[i] && memchr(av[i], '/', (size_t)(eq - av[i])) == NULL) {
                *eq = '\0';
                setenv(av[i], eq + 1, 1);
                i++;
            } else {
                break;
            }
        }
        int w = i;
        for (int j = i; j < ac; j++) {
            if (strcmp(av[j], "2>&1") == 0) {
                dup2(1, 2);
            } else {
                av[w++] = av[j];
            }
        }
        av[w] = NULL;
        if (w == i) _exit(0);
        execvp(av[i], &av[i]);
        _exit(127);
    }
    int st = 0;
    waitpid(pid, &st, 0);
    free(buf);
    free(av);
    return y_mk_long(WIFEXITED(st) ? WEXITSTATUS(st) : -1);
}
YValue *y_builtin_exit(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    long code = 0;
    if (argc > 0 && args[0]->type == Y_LONG) code = args[0]->data.l;
    exit((int)code);
}
static int g_argc = 0;
static char **g_argv = NULL;
void y_set_argv(int argc, char **argv) {
    g_argc = argc;
    g_argv = argv;
}
YValue *y_builtin_argv(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    (void)args;
    (void)argc;
    YValue **elements = malloc(sizeof(YValue *) * (g_argc > 0 ? g_argc : 1));
    for (int i = 0; i < g_argc; i++) {
        elements[i] = y_mk_str(g_argv[i]);
    }
    YValue *arr = y_mk_arr(elements, g_argc);
    free(elements);
    return arr;
}
YValue *y_builtin_tonum(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1) return y_mk_long(0);
    if (args[0]->type == Y_LONG) return y_mk_long(args[0]->data.l);
    if (args[0]->type == Y_FLOAT) return y_mk_long((long)args[0]->data.f);
    if (args[0]->type != Y_STR) return y_mk_long(0);
    char *end;
    long v = strtol(args[0]->data.s, &end, 10);
    if (end == args[0]->data.s) return y_mk_long(0);
    return y_mk_long(v);
}
YValue *y_builtin_join(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_ARR || args[1]->type != Y_STR)
        return y_mk_str("");
    YArray *arr = args[0]->data.arr;
    const char *delim = args[1]->data.s;
    size_t total = 0;
    char **parts = malloc(sizeof(char *) * (arr->count > 0 ? arr->count : 1));
    for (size_t i = 0; i < arr->count; i++) {
        parts[i] = y_to_str(arr->elements[i]);
        total += strlen(parts[i]);
    }
    total += strlen(delim) * (arr->count > 0 ? arr->count - 1 : 0) + 1;
    char *result = malloc(total);
    result[0] = '\0';
    for (size_t i = 0; i < arr->count; i++) {
        if (i > 0) strcat(result, delim);
        strcat(result, parts[i]);
        free(parts[i]);
    }
    free(parts);
    YValue *v = malloc(sizeof(YValue));
    v->type = Y_STR;
    v->data.s = result;
    return v;
}
YValue *y_builtin_push(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_ARR) return y_mk_arr(NULL, 0);
    y_arr_cow(args[0]);
    YArray *a = args[0]->data.arr;
    a->elements = realloc(a->elements, sizeof(YValue *) * (a->count + 1));
    a->elements[a->count] = args[1]; 
    a->count++;
    args[1] = NULL; 
    YValue *result = args[0];
    args[0] = NULL; 
    return result;
}
YValue *y_builtin_substr(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 3 || args[0]->type != Y_STR) return y_mk_str("");
    const char *s = args[0]->data.s;
    long slen = (long)strlen(s);
    long start = args[1]->data.l;
    long count = args[2]->data.l;
    if (start < 0) start = 0;
    if (start >= slen) return y_mk_str("");
    if (count < 0 || start + count > slen) count = slen - start;
    return y_mk_str_n(s + start, (size_t)count);
}
YValue *y_builtin_read_file(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR) return y_mk_null();
    FILE *f = fopen(args[0]->data.s, "rb");
    if (!f) return y_mk_null();
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz < 0) { fclose(f); return y_mk_null(); }
    char *buf = malloc((size_t)sz + 1);
    size_t rd = fread(buf, 1, (size_t)sz, f);
    buf[rd] = '\0';
    fclose(f);
    YValue *v = malloc(sizeof(YValue));
    v->type = Y_STR;
    v->data.s = buf;
    return v;
}
YValue *y_builtin_write_file(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_STR || args[1]->type != Y_STR)
        return y_mk_bool(false);
    FILE *f = fopen(args[0]->data.s, "wb");
    if (!f) return y_mk_bool(false);
    size_t n = strlen(args[1]->data.s);
    size_t wr = fwrite(args[1]->data.s, 1, n, f);
    fclose(f);
    return y_mk_bool(wr == n);
}
YValue *y_builtin_ord(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR || args[0]->data.s[0] == '\0')
        return y_mk_long(-1);
    return y_mk_long((long)(unsigned char)args[0]->data.s[0]);
}
YValue *y_builtin_chr(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1) return y_mk_str("");
    char buf[2] = { (char)(args[0]->data.l & 0xFF), '\0' };
    return y_mk_str_n(buf, 1);
}
YValue *y_builtin_index_of(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_STR || args[1]->type != Y_STR)
        return y_mk_long(-1);
    const char *hit = strstr(args[0]->data.s, args[1]->data.s);
    if (!hit) return y_mk_long(-1);
    return y_mk_long((long)(hit - args[0]->data.s));
}
YValue *y_builtin_arr_index_of(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_ARR)
        return y_mk_long(-1);
    YArray *arr = args[0]->data.arr;
    for (size_t i = 0; i < arr->count; i++) {
        if (y_equals(arr->elements[i], args[1]))
            return y_mk_long((long)i);
    }
    return y_mk_long(-1);
}
YValue *y_builtin_last_index_of(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 2 || args[0]->type != Y_STR || args[1]->type != Y_STR)
        return y_mk_long(-1);
    const char *hay = args[0]->data.s;
    const char *needle = args[1]->data.s;
    size_t nlen = strlen(needle);
    if (nlen == 0) return y_mk_long((long)strlen(hay));
    const char *last = NULL;
    for (const char *p = hay; (p = strstr(p, needle)) != NULL; p++)
        last = p;
    if (!last) return y_mk_long(-1);
    return y_mk_long((long)(last - hay));
}
YValue *y_builtin_getenv(YScope *closure, YValue **args, size_t argc) {
    (void)closure;
    if (argc < 1 || args[0]->type != Y_STR)
        return y_mk_null();
    const char *val = getenv(args[0]->data.s);
    if (!val) return y_mk_null();
    return y_mk_str(val);
}
void y_arr_set(YValue *arr, YValue *idx, YValue *val) {
    if (arr->type != Y_ARR) {
        fprintf(stderr, "runtime error: arr_set target is not an array\n");
        exit(1);
    }
    y_arr_cow(arr); 
    long i = idx->data.l;
    long count = (long)arr->data.arr->count;
    if (count == 0) {
        fprintf(stderr, "runtime error: array index out of bounds (empty)\n");
        exit(1);
    }
    i = (i % count + count) % count; 
    y_free(arr->data.arr->elements[i]);
    arr->data.arr->elements[i] = val;
}
char *y_escape_c_string(const char *s, size_t len) {
    char *out = malloc(len * 4 + 1);
    size_t j = 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '\\': out[j++] = '\\'; out[j++] = '\\'; break;
        case '"': out[j++] = '\\'; out[j++] = '"'; break;
        case '\n': out[j++] = '\\'; out[j++] = 'n'; break;
        case '\t': out[j++] = '\\'; out[j++] = 't'; break;
        case '\r': out[j++] = '\\'; out[j++] = 'r'; break;
        default:
            if (c < 32 || c > 126) {
                j += sprintf(out + j, "\\%03o", c);
            } else {
                out[j++] = (char)c;
            }
        }
    }
    out[j] = '\0';
    return out;
}
