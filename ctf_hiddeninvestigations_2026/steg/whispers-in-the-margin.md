# Whispers in the Margin

Steganography, 55 points, 526 solves. Two handouts: a Word document whose last fifty
paragraphs look empty, and a photograph. The empty paragraphs are not empty. They hold a
program written in the Whitespace esoteric language, and what it prints is the passphrase
for the image.

## What you are given

`whispers-in-the-margin.zip` expands to a directory `chall/` holding two files:

```
chall.jpg                                4,631,691 bytes, 5182 x 3455, JFIF 1.02
Those numbers are process counts.docx       14,032 bytes
```

There is no live service and no login material.

## Reproduction

1. Unpack the DOCX as a ZIP and list its parts. There are twelve: `[Content_Types].xml`,
   `_rels/.rels`, `word/_rels/document.xml.rels`, `word/document.xml`,
   `word/theme/theme1.xml`, `word/settings.xml`, `word/webSettings.xml`,
   `word/styles.xml`, `word/numbering.xml`, `word/fontTable.xml`, `docProps/core.xml` and
   `docProps/app.xml`. There is no archive comment, no extra part and no data after the
   end of central directory, so the document is not padded with a second payload.

2. Read the document. The visible text is a chat style answer about Task Manager: why one
   browser tab shows fifteen or twenty processes, what each process does, and how to
   expand the list. The first paragraph sets the tone for the trick: "Those numbers are
   process counts, not tab counts." The metadata is unremarkable, three pages and 234
   words according to `app.xml`, created and modified on 2026-09-09.

3. Search the XML for the usual DOCX hiding places and find nothing. There are no runs
   with `w:vanish` (hidden text), no white coloured runs, no zero sized runs, no comments
   part and no tracked revisions. That rules out the two obvious ways to hide words in a
   Word file.

4. Look at what is left, which is the tail of the body. `word/document.xml` holds 62
   paragraphs. The first nine carry the visible text. The next 51 contain nothing but
   spaces and `<w:tab/>` elements, and only a final pair of truly empty paragraphs sits
   between them and the section properties. A page of blank paragraphs at the end of a
   document is the kind of thing nobody scrolls to, and whitespace is exactly the
   alphabet that the Whitespace language uses.

5. Turn the XML back into characters. Each `<w:tab/>` becomes a tab (0x09), every literal
   space in a `w:t` element stays a space (0x20), and each paragraph boundary becomes a
   linefeed (0x0A). Keep only those three bytes and drop everything else. The result is a
   378 character program: 210 spaces, 115 tabs and 53 newlines. Whitespace has exactly
   three significant characters, space, tab and linefeed, so a stream built from those
   three bytes is a complete program with no residue.

6. Run it through any Whitespace interpreter. The output is:

   ```
   haha! u got me, now what?
   ```

   In our run the interpreter printed that line immediately and then kept executing until
   the step cap, so the program does not reach its halt instruction in a naive read. The
   printed string is the payload either way. Note that the message is a taunt, not a flag,
   which is the point: the document was a key delivery mechanism, not the answer.

7. Use that string, exactly as printed, including the exclamation mark and the question
   mark, as the steghide passphrase on the photograph:

   ```sh
   steghide extract -sf chall.jpg -p 'haha! u got me, now what?' -xf out.bin
   ```

   Quoting matters. The exclamation mark is a history expansion character in interactive
   bash, and an unquoted or double quoted command can mangle it. Single quotes, or a
   passphrase read from a file, avoid the problem entirely.

8. Confirm the carrier was worth approaching. `chall.jpg` is 4,631,691 bytes, 5182 by
   3455, JFIF 1.02 at 72 dpi. The EOI marker is the last two bytes, there is no EXIF, no
   comment segment and no `hiCTF` string anywhere in the file, so a plain container
   inspection comes back empty and a coefficient domain tool is the right next step.

9. Account for what the local record does not contain. The team log records the passphrase
   and the accepted flag, and the submission followed the note by about two minutes. The
   embedded file name and payload size inside `chall.jpg` were not written down, and the
   steghide build used at the time is no longer present in this workspace, so the
   extraction step cannot be re-run here. The passphrase and the result are the recorded
   facts; the intermediate steghide `info` output for this image is not.

## Why it works

A Word paragraph that contains only spaces and tabs renders as blank space, and Word
stores each tab as an element rather than as a character, so the sequence survives a
round trip through the editor and through any text extraction that trims whitespace. A
document that ends with a page of empty paragraphs looks like sloppy formatting, not like
a payload.

The choice of Whitespace as the encoder is what makes the trick work: its entire alphabet
is invisible on a page, so the program can live in the layout of a document without any
of it appearing as text. The follow-on step is a normal steghide extraction where the
passphrase happens to be a sentence produced by the document, which is why the artifact
looks like two unrelated files until the two are joined.

## Flag

```
hiCTF{573g4n0gr4phy_!5_fun}
```
