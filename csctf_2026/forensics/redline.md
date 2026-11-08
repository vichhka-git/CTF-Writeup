# Redline

**Category:** Forensics · **Points:** 200 · **Flag:** `CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`

## What the handout gives you

The handout provides a single Word processing document outlining medical cold-chain protocols during an operational power grid incident.

- `CC-11_excursion_directive.docx` — 3,817 bytes, Microsoft Word 2007+ document (ZIP archive containing OpenXML files).

## Walkthrough

1. **Unpack the OpenXML package.** A `.docx` file is a standard PKZIP container holding XML markup, relationship files, and metadata trees. Unpacking the archive exposes the internal directory tree:

```bash
unzip -q CC-11_excursion_directive.docx -d unpacked
```

2. **Inspect document metadata.** Check `unpacked/docProps/core.xml` for package provenance. The Dublin Core properties establish that `A. Reyes` authored the directive on `2026-10-06T14:02:00Z`. The file indicates revision counter 4 and records that user `s.kessler` saved the final modifications on `2026-10-07T02:41:00Z`.

3. **Locate main document markup.** The primary text resides in `unpacked/word/document.xml`. Microsoft Word logs Track Changes revisions directly within this XML tree using `<w:del>` (deletions) and `<w:ins>` (insertions). Each revision element includes attributes documenting the author name, a unique revision identifier, and a UTC timestamp.

4. **Examine tracked modifications.** Reviewing `unpacked/word/document.xml` shows that `s.kessler` made multiple changes at `2026-10-07T02:41:00Z`. Early in the text, Kessler replaced "temperature" with "thermal" (revision IDs 101 and 102) and modified the threshold time before alerting Nightwatch from 30 minutes to 90 minutes (revision IDs 103 and 104).

5. **Analyze the altered directives.** Paragraph 4 defines the disposition of breached medicine stock. The visible body text instructs depot crews that vials exceeding 8°C may be returned to distribution at depot-supervisor discretion under authorization `CSCTF{dispatch_0f7c0c00aac69bbb86d6b96391f5d112}`. Directly preceding that insertion run, `<w:del w:id="105">` contains the approved directive text: "Vials that exceeded 8 C MUST be quarantined and MUST NOT be redistributed. Excursion authorization: ".

6. **Extract the original authorization.** The original authorization string was struck out immediately following the quarantine order. Microsoft Word fragmented the deleted token across two separate XML runs inside adjacent deletion tags:
   - `<w:del w:id="107">` wraps `<w:delText xml:space="preserve">CSCTF{redline_21ee9b19d</w:delText>`
   - `<w:del w:id="108">` wraps `<w:delText xml:space="preserve">342e06432165fb2b6f64e06}</w:delText>`
   - `<w:del w:id="109">` wraps the trailing punctuation `<w:delText xml:space="preserve">.</w:delText>`

7. **Concatenate the deleted segments.** Concatenating the text from revision 107 and revision 108 reconstructs the complete original authorization token: `CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`.

## Answer

Recombining the deleted XML nodes recovers the approved authorization code:

`CSCTF{redline_21ee9b19d342e06432165fb2b6f64e06}`

## Notes

The document package also includes `word/comments.xml`. In comment ID 1, author `s.kessler` explicitly justifies the changes: "Per tonight's dispatch throughput directive I am dropping the quarantine hold - Depot 7 backlog is too high to sideline stock. Re-issuing under a fresh authorization." The visible insertion `CSCTF{dispatch_...}` was an unapproved override submitted during the incident.
