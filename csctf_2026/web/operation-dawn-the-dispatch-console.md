# Operation Dawn: The Dispatch Console

**Category:** Web · **Points:** 540 · **Flag:** `CSCTF{qY5mizeGrh0B276iYLVWARLm}`

## What the handout gives you

A posting board for field dispatches: `/` lists posts, `/post` submits one, `/digest`
compiles a duty digest for a callsign, and `/report` renders a summary. The brief asks for
the command operator's token, which the console keeps in its own database.

## Walkthrough

1. **Map the routes and the filter.** Submitting a post with the words `UNION`, `SELECT`
   or `--` returns a block page. URL-encoding those characters in the body gets the post
   stored, so the filter inspects the raw request and the application decodes it later.

2. **Test for storage.** The callsign is echoed on `/` and used again by `/digest`, which
   is two writes of the same string in different contexts — the classic setup for
   second-order injection. Put a single quote in the callsign when posting and the digest
   page answers with a database error.

3. **Read the digest query.** The error shows the statement being compiled:
   `SELECT body FROM dispatches WHERE callsign = '<callsign>'`. The callsign goes in
   unparameterised, and the filter that guards `/post` does not run when `/digest`
   compiles its query.

4. **Post a payload instead of a callsign.** Store something that closes the quote and
   unions in the operators table, with the columns concatenated so they survive as text.
   Sorting the stored value by callsign also decides whose digest is compiled, so pick a
   callsign that the digest page will actually request.

5. **Fetch the digest.** Loading `/digest` for that callsign returns the injected rows.
   Among them is the command operator `WARDEN` with a token beginning `AC-`.

6. **Use the token.** `/report` accepts a token and a format string. Passing a format
   expression that reaches into the dispatch object's class and its globals dumps the
   module globals, and the flag is in them. The token check is the only gate, so the
   recovered `AC-` value is enough.

## Answer

`CSCTF{qY5mizeGrh0B276iYLVWARLm}`

## Notes

The filter on the first route is a red herring: it blocks keywords in the request body but
never sees the query that the second route builds. Encoding the body simply gets the
payload past the first check and into storage intact.

The format-string step is a separate bug from the injection. The token gives you the
privilege; the format expression gives you the read.
