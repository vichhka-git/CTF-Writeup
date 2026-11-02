# Shadow Identity

OSINT, 53 points, 745 solves. One photograph is supplied and the task is to name the person in it. Nothing is hidden inside the file. The image is a promotional poster that names an event and a year, so the work is to resolve that edition to its titleholder and then choose the right spelling of the name.

## What you are given

`shadow-identity.zip` expands to `miss_grand.jpeg`, 481x636, RGB, 63,052 bytes. The description supplies the format and an example: `hiCTF{rahim_ahmed_meow}`. Everything is lowercase, with underscores between name parts.

## Reproduction

1. Confirm there is nothing to extract. The JPEG has no EXIF at all, and the file ends exactly at `ffd9` with no appended data, so there is no stego layer and no embedded payload:

```sh
python3 -c "from PIL import Image; i=Image.open('miss_grand.jpeg'); print(i.size, i.mode, dict(i.getexif()))"
tail -c 2 miss_grand.jpeg | xxd
```

Both checks come back empty or clean, and the local notes record the same result. The only content is what you can see.

2. Read the poster as a poster, not as a portrait. It is a stylised pageant graphic: an emerald mosaic crown and gown in Miss Grand house style, the Tanzanian flag and Kilimanjaro behind the figure, and baked-in title text reading `MISS GRAND TANZANIA 2026`. The text is part of the image, not a caption you can query, which is why the solve starts with reading it.

3. Treat the title text as the pivot. It names an event edition, and an edition has exactly one titleholder. Search that string as a phrase; the Miss Grand Tanzania titleholder list and the reporting around the 2026 edition both surface directly from it.

4. Resolve the edition to a person. The Miss Grand Tanzania titleholder list gives 2026 as Jihan Dimack. Contemporary reporting on the same edition gives the fuller published form, Jihan Mohin Dimack, in the first body paragraph rather than the headline. A profile page for the same titleholder lists it explicitly as her full name (`Nama Lengkap`). Two independent body-copy uses of the three-token form are the evidence for the answer.

5. Note how many spellings are in circulation before choosing one. The same public figure appears as a short two-token press form, as a fuller three-token form, and as a variant surname ending in `dimachk` used in some infoboxes and contestant-page slugs. The checker compares exact strings, so a form that identifies the right person can still be the wrong answer. Body copy beats headline copy here.

6. Normalise the chosen form to the flag format. Lowercase the name and replace spaces with underscores:

```
Jihan Mohin Dimack  ->  hiCTF{jihan_mohin_dimack}
```

7. Expect the two near misses and know why they fail. The short two-token form is the name used in article titles and in the pageant organisation's own introduction; it was submitted and rejected. The `dimachk` variant is the form used in some published profiles; it was also submitted and rejected. The accepted string appears verbatim in the news and profile copy, and it is not assembled by mixing the rejected forms.

8. Record the attribution limit. The poster's original publication page and caption were never located, so the identification rests on the event text plus the titleholder record. It is an event-level identification, not a photo-level one, and the local notes say so explicitly rather than claiming a facial match.

9. Expect some sources to be closed. In the local session the pageant's bare profile URL and the archived snapshot of it both failed, while the search-indexed profile text and two news pages opened normally. That is why the answer rests on body copy from more than one outlet rather than on a single official page.

## Why it works

The poster does most of the identification itself by naming the event and the year. What remains is a name-spelling problem: the same public figure appears under a short form, a fuller published form, and a variant with `dimachk`. The description asks for the full name, and the full published three-token form is the one the sources use in body copy. The example flag's three tokens are suggestive, but the notes are explicit that the example does not by itself require three tokens.

The rejections are part of the trail. They show that the checker wants the published full form, not the search-friendly short form, so an answer built from the first headline that matches the poster will be wrong even though every source agrees on the underlying person.

## Flag

```
hiCTF{jihan_mohin_dimack}
```
