#ifndef YRUNTIME_H
#define YRUNTIME_H
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
typedef enum {
    Y_LONG,
    Y_FLOAT,
    Y_BOOL,
    Y_STR,
    Y_NULL,
    Y_ARR,
    Y_MAP,
    Y_FUNC,
} YType;
typedef struct YValue YValue;
typedef struct {
    int refcount;
    size_t count;
    YValue **elements;
} YArray;
typedef struct {
    char *key;
    YValue *value;
} YMapEntry;
typedef struct {
    int refcount;
    size_t count;
    YMapEntry *entries;
} YMap;
struct YScope;
typedef YValue *(*YFuncPtr)(struct YScope *closure, YValue **args,
                            size_t argc);
typedef struct {
    YFuncPtr fn;
    size_t arity;
    struct YScope *closure;
} YFunc;
struct YValue {
    YType type;
    union {
        long l;
        double f;
        bool b;
        char *s;
        YArray *arr;
        YMap *map;
        YFunc *func;
    } data;
};
typedef struct YScopeEntry {
    char *name;
    YValue *value;
    struct YScopeEntry *next;
} YScopeEntry;
typedef struct YScope {
    YScopeEntry *entries;
    struct YScope *parent;
    int refcount;
} YScope;
YValue *y_mk_long(long v);
YValue *y_mk_float(double v);
YValue *y_mk_bool(bool v);
YValue *y_mk_str(const char *s);
YValue *y_mk_str_n(const char *s, size_t len);
YValue *y_mk_null(void);
YValue *y_mk_arr(YValue **elements, size_t count);
YValue *y_mk_map(YMapEntry *entries, size_t count);
YValue *y_mk_func(YFuncPtr fn, size_t arity, YScope *closure);
void y_scope_init(YScope *scope, YScope *parent);
YScope *y_scope_retain(YScope *scope);
void y_scope_release(YScope *scope);
YValue *y_scope_get(YScope *scope, const char *name);
YValue *y_scope_take(YScope *scope, const char *name);
void y_scope_set(YScope *scope, const char *name, YValue *value);
void y_scope_set_local(YScope *scope, const char *name, YValue *value);
YValue *y_clone(YValue *val);
void y_free(YValue *val);
char *y_to_str(YValue *val);
void y_print(YValue *val);
bool y_equals(YValue *a, YValue *b);
YValue *y_add(YValue *a, YValue *b);
YValue *y_sub(YValue *a, YValue *b);
YValue *y_mul(YValue *a, YValue *b);
YValue *y_div(YValue *a, YValue *b);
YValue *y_mod(YValue *a, YValue *b);
YValue *y_lt(YValue *a, YValue *b);
YValue *y_gt(YValue *a, YValue *b);
YValue *y_lte(YValue *a, YValue *b);
YValue *y_gte(YValue *a, YValue *b);
YValue *y_eq(YValue *a, YValue *b);
YValue *y_neq(YValue *a, YValue *b);
YValue *y_and(YValue *a, YValue *b);
YValue *y_or(YValue *a, YValue *b);
YValue *y_neg(YValue *a);
YValue *y_arr_index(YValue *arr, YValue *idx);
YValue *y_arr_index_borrow(YValue *arr, YValue *idx);
YValue *y_arr_slice(YValue *arr, YValue *start, YValue *end);
YValue *y_map_get(YValue *map, const char *key);
YValue *y_cons(YValue *head, YValue *tail);
YValue *y_call(YValue *callee, YValue **args, size_t argc);
YValue *y_builtin_print(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_tostring(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_range(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_typeof(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_readline(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_clear_eof(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_puts(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_split(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_len(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_trim(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_exec(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_spawn(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_exit(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_argv(YScope *closure, YValue **args, size_t argc);
void y_set_argv(int argc, char **argv);
YValue *y_builtin_tonum(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_join(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_push(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_substr(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_read_file(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_write_file(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_ord(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_chr(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_index_of(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_arr_index_of(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_last_index_of(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_getenv(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_map_set(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_map_get(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_global_get(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_scope_new(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_scope_def(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_scope_find(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_scope_get(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_scope_set(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_tok_type(YScope *closure, YValue **args, size_t argc);
YValue *y_builtin_tok_value(YScope *closure, YValue **args, size_t argc);
void y_arr_set(YValue *arr, YValue *idx, YValue *val);
char *y_escape_c_string(const char *s, size_t len);
#endif
