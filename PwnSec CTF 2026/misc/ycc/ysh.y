const VERSION = { major: 6, minor: 7 };
const SRC_PATH = "/tmp/_ysh_eval.y";
const OUT_PATH = "/tmp/_ysh_out";

def banner() {
    puts("    ▌ \n▌▌▛▘▛▌\n▙▌▄▌▌▌\n▄▌     \n" + VERSION.major + "." + tostring(VERSION.minor) + " — type 'help' for commands\n");
};

def show_help() -> long {
    puts("commands:\n");
    puts("  help              show this help\n");
    puts("  echo <args...>    print arguments\n");
    puts("  eval              run y code: eval \"<code>\" or bare 'eval' + code + ctrl-D\n");
    puts("  calc <expr...>    infix math -> RPN -> stack eval, supports + - * / % ( )\n");
    puts("  rev <args...>     reverse argument order\n");
    puts("  count <args...>   count arguments\n");
    puts("  seq <n>           print 1..n\n");
    puts("  fib <n>           nth fibonacci number\n");
    puts("  exit              quit the shell\n");
    0
};

def has_non_ascii(s: str) -> bool {
    let found = false;
    foreach (i in range(len(s))) {
        if (!found && ord(substr(s, i, 1)) > 127) {
            found = true;
        };
    };
    found
};

def run_src(src: str) -> long {
    if (has_non_ascii(src)) {
        puts("eval rejected: non-ascii input\n");
        return 1;
    };
    write_file(SRC_PATH, src);
    let rc = exec("YCC_RUNTIME_DIR=/app /app/ycc --no-exec --no-io --compile " + SRC_PATH + " -o " + OUT_PATH + " 2>&1");
    if (rc != 0) {
        puts("compile failed (exit " + tostring(rc) + ")\n");
        return rc;
    };
    exec(OUT_PATH)
};

def read_eval_body() -> long {
    let lines = [];
    let line = readline();
    while (line != null) {
        lines = push(lines, line);
        line = readline();
    };
    clear_eof();
    let src = join(lines, "\n");
    if (len(trim(src)) == 0) {
        return 1;
    };
    run_src(src)
};

def cmd_eval(args: [str]) -> long {
    if (len(args) < 2) {
        return read_eval_body();
    };
    let code = join(args[1:], " ");
    if (len(code) > 1 && substr(code, 0, 1) == "\"" && substr(code, len(code) - 1, 1) == "\"") {
        code = substr(code, 1, len(code) - 2);
    };
    if (len(trim(code)) == 0) {
        return read_eval_body();
    };
    run_src(code)
};

def op_prec(op: str) -> long {
    if (op == "*" || op == "/" || op == "%") {
        2
    } else if (op == "+" || op == "-") {
        1
    } else {
        0
    }
};

def to_rpn(toks: [str]) -> [str] {
    let out = [];
    let ops = ["", "", "", "", "", "", "", "", "", "", "", "", "", "", "", ""];
    let sp = 0;
    foreach (tok in toks) {
        if (op_prec(tok) > 0) {
            while (sp > 0 && ops[sp - 1] != "(" && op_prec(ops[sp - 1]) >= op_prec(tok)) {
                out = push(out, ops[sp - 1]);
                sp = sp - 1;
            };
            ops[sp] = tok;
            sp = sp + 1;
        } else if (tok == "(") {
            ops[sp] = tok;
            sp = sp + 1;
        } else if (tok == ")") {
            while (sp > 0 && ops[sp - 1] != "(") {
                out = push(out, ops[sp - 1]);
                sp = sp - 1;
            };
            if (sp > 0) {
                sp = sp - 1;
            };
        } else {
            out = push(out, tok);
        };
    };
    while (sp > 0) {
        out = push(out, ops[sp - 1]);
        sp = sp - 1;
    };
    out
};

def op_apply(op: str, a: long, b: long) -> long {
    if (op == "+") {
        a + b
    } else if (op == "-") {
        a - b
    } else if (op == "*") {
        a * b
    } else if (op == "/") {
        a / b
    } else {
        a % b
    }
};

def calc(rpn: [str]) -> long {
    let st = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    let sp = 0;
    foreach (tok in rpn) {
        if (op_prec(tok) > 0) {
            let b = st[sp - 1];
            let a = st[sp - 2];
            sp = sp - 1;
            st[sp - 1] = op_apply(tok, a, b);
        } else {
            st[sp] = tonum(tok);
            sp = sp + 1;
        };
    };
    st[0]
};

def cmd_calc(args: [str]) -> long {
    puts(tostring(calc(to_rpn(args[1:]))) + "\n");
    0
};

def cmd_echo(args: [str]) -> long {
    puts(join(args[1:], " ") + "\n");
    0
};

def cmd_rev(args: [str]) -> long {
    let out = [];
    foreach (a in args[1:]) {
        out = a :: out;
    };
    puts(join(out, " ") + "\n");
    0
};

def cmd_count(args: [str]) -> long {
    puts(tostring(len(args) - 1) + "\n");
    0
};

def cmd_seq(args: [str]) -> long {
    if (len(args) < 2) {
        puts("usage: seq <n>\n");
        return 1;
    };
    foreach (i in range(tonum(args[1]))) {
        puts(tostring(i + 1) + "\n");
    };
    0
};

def fib(n: long) -> long {
    if (n < 2) {
        n
    } else {
        fib(n - 1) + fib(n - 2)
    }
};

def cmd_fib(args: [str]) -> long {
    if (len(args) < 2) {
        puts("usage: fib <n>\n");
        return 1;
    };
    puts(tostring(fib(tonum(args[1]))) + "\n");
    0
};

def cmd_exit(t: [str]) -> long {
    1
};

const HANDLERS = {
    echo: cmd_echo,
    calc: cmd_calc,
    rev: cmd_rev,
    count: cmd_count,
    seq: cmd_seq,
    fib: cmd_fib,
    help: show_help,
    exit: cmd_exit,
    quit: cmd_exit,
    eval: def (args: [str]) -> long {
        cmd_eval(args);
        0
    }
};

def dispatch(line: str) -> long {
    let trimmed = trim(line);
    if (len(trimmed) == 0) {
        0
    } else {
        let tokens = split(trimmed, " ");
        let h = map_get(HANDLERS, tokens[0]);
        if (h == null) {
            puts("ysh: unknown command: " + tokens[0] + "\n");
            0
        } else {
            h(tokens)
        }
    }
};

def cmd_run_line(line: str) -> long {
    let segs = split(line, ";");
    if (len(segs) > 1) {
        let last = 0;
        foreach (s in segs) {
            last = cmd_run_line(s);
        };
        return last;
    };
    let trimmed = trim(line);
    if (len(trimmed) == 0) {
        return 0;
    };
    let tokens = split(trimmed, " ");
    if (tokens[0] == "exit" || tokens[0] == "quit") {
        if (len(tokens) > 1) {
            return tonum(tokens[1]);
        };
        return 0;
    };
    if (tokens[0] == "eval") {
        return cmd_eval(tokens);
    };
    if (map_get(HANDLERS, tokens[0]) != null) {
        return dispatch(trimmed);
    };
    spawn(trimmed)
};

let args = argv();
if (len(args) > 1) {
    if (args[1] == "-c") {
        if (len(args) > 2) {
            exit(cmd_run_line(join(args[2:], " ")));
        };
        puts("ysh: -c: option requires an argument\n");
        exit(2);
    };
};

banner();
let running = true;
while (running) {
    puts("y> ");
    let line = readline();
    if (line == null) {
        puts("\n");
        running = false;
    } else {
        if (dispatch(line) == 1) {
            running = false;
        };
    };
};
