# Overgrowth

Web, 73 points, 134 solves. A Flask plus Ariadne GraphQL API for a gardening
supply store. Introspection is disabled. The flag is a field that only the head
gardener is allowed to pick, so the job is account takeover of the seeded admin.

## What you are given

The portal supplies `<challenge-host>` and `<port>`. There are no attached
files and no source. The API is a single `/graphql` endpoint, POST only. The
description is short: "The flag is just a field, one that only the head
gardener is allowed to pick."

## Reproduction

1. Recover the schema from error suggestions. `{__schema{types{name}}}` is
   blocked, so send fields that do not exist and read the "did you mean"
   responses. The root types are:

   ```
   Query{ me:User, user(username:String!):User, products:[Product!]!, flag:String }
   Mutation{ login(username,password):AuthPayload,
             requestPasswordReset(username):Boolean!,
             resetPassword(username,token,newPassword):Boolean! }
   User{ id username email role apiKey }
   Product{ id name price }        AuthPayload{ token user }
   ```

2. Confirm the access rule on `flag`. `{ flag }` without credentials answers
   that authentication is required, and `{ me }` is null. The anonymous
   `user(username:"admin")` query does return the record, including `apiKey`,
   `role` and `email`. That is a broken object level authorization, but the
   returned admin `apiKey` is a planted decoy whose own text says it is not the
   flag. Treat it as a red herring.

3. Check what login issues. `login` returns an opaque bearer token in
   `AuthPayload`. The `apiKey` did not authenticate in any carrier we tried
   (header, cookie, query string, Basic auth, JSON body), and forged JWTs and
   itsdangerous cookies failed. With no genuine token sample, token forgery was
   blind, which is why earlier attempts on this challenge parked.

4. Read the reset path instead. `requestPasswordReset(username:"admin")`
   returns true and sets a four-digit numeric reset token. `resetPassword`
   accepts a username, a token and a new password, and it is the mutation that
   consumes the token. A per-request limiter protects it: our manual attempts
   returned 429 after about five reset calls.

5. Batch the guesses into one HTTP request. GraphQL aliases let a single
   operation carry thousands of root fields. Build one mutation with 10000
   aliased `resetPassword` calls, one per token from `0000` to `9999`:

   ```
   mutation{ a0000:resetPassword(username:"admin",token:"0000",newPassword:"<new>")
             a0001:resetPassword(username:"admin",token:"0001",newPassword:"<new>")
             ... }
   ```

   The limiter counts the request, not the resolvers. The response `data` object
   carries one key per alias, and the alias whose value is `true` identifies the
   OTP and has already set the new password.

6. Log in and read the flag.

   ```
   mutation{ login(username:"admin",password:"<new>"){ token } }
   { flag me{username role} }        Authorization: Bearer <token>
   ```

   The recorded response carried the flag in `data.flag` and
   `me` set to `{"role":"admin","username":"admin"}`.

7. Control run. The same chain against the low-privilege seeded account
   `sprout` recovered OTP `1374` and produced a valid session, which shows the
   batching path rather than a lucky guess. The admin OTP from our live run is
   not recorded in the local notes; the writeup mentions `8050` only as an
   illustrative example.

Two record notes. The submission log has no row for Overgrowth, so the local
record is the run result: `flag_verified: true`, provenance
`command-output` from the solve run, and the captured flag query response quoted
above. A portal submission transcript for this challenge is not in the local
record. The exact request count seen by the limiter and the server's response
time are also not recorded.

## Why it works

Two weak choices compound. The reset token is a four-digit numeric value, so the
whole keyspace is 10000 candidates. The rate limiter is applied per HTTP
request, while GraphQL resolves every aliased field inside that request. One
request therefore buys 10000 resolver calls, and the entire keyspace is tested
inside the limiter's budget. The successful alias both reveals the OTP and sets
the attacker's password, so the account takeover completes without any other
step. The fixes are strong single-use reset tokens, and rate or cost limits
counted per resolver operation with aliased field duplication treated as
separate work.

## Flag

```
hiCTF{graphql_al1as_batch1ng_brute_f0rces_the_0tp_bb17f07f98}
```
