import base64
import os
import io
import pickle
import pickletools

from flask import Flask, jsonify, render_template, request

import sessionstore  # noqa: F401


BANNED_PATTERNS = [
    b".",
    b"os", b"system", b"popen", b"subprocess", b"commands",
    b"exec", b"eval", b"import", b"getattr", b"setattr",b"flag"
]
BANNED_INSTRUCTION = "REDUCE"

ALLOWED_MODULES = {"sessionstore", "collections"}


class RestrictedUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if module.split(".")[0] not in ALLOWED_MODULES:
            raise pickle.UnpicklingError("module %r is not allowed" % module)
        return super().find_class(module, name)


def check(data):
    for pattern in BANNED_PATTERNS:
        if pattern in data:
            raise ValueError("Payload contains banned characters!")
    out = io.StringIO()
    try:
        pickletools.dis(data, out=out)
        disassembled = out.getvalue()
        if BANNED_INSTRUCTION in disassembled:
            raise ValueError("Payload contains banned instruction: %s" % BANNED_INSTRUCTION)
    except Exception:
        disassembled = "Error!"
    return disassembled


def restore(raw_b64):
    import contextlib
    data = base64.b64decode(raw_b64)
    disassembled = check(data)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            RestrictedUnpickler(io.BytesIO(data)).load()
        except Exception:
            pass
    return buf.getvalue(), disassembled


app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/restore")
def restore_route():
    payload = (request.get_json(silent=True) or {}).get("payload", "")
    try:
        output, disassembled = restore(payload)
        return jsonify(ok=True, output=output, disassembled=disassembled)
    except Exception as exc:
        return jsonify(ok=False, error=str(exc), disassembled="Error!")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=9999)