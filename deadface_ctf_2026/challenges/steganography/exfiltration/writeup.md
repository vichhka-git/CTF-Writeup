# Exfiltration

- **Category:** Steganography
- **Points:** 75
- **Flag:** `deadface{timing-is-everything}`

## Challenge

DEADFACE frequently uses unconventional methods to exchange information and avoid detection. Analysts recovered a set of images from a compromised communications channel that appear unrelated at first glance. We suspect the collection contains a hidden message intended for other members of the group. Recover the message and identify what DEADFACE is trying to say. Submit the answer as `deadface{flagtext}`. [Download File](https://deadface.sfo3.cdn.digitaloceanspaces.com/2026/challenges/steg/exfiltration.zip) (556 KB) SHA1: `ee1186a1bcbce4269e31db58ead46d171e97c17805983cce827822ba36120be3`

## Solution

Steps
1. Sort all 20 images chronologically by their EXIF `DateTimeOriginal` timestamp: - `14:02:17` (`image_07.jpg`) -> `IMG_6465` -> `de` - `14:04:52` (`image_14.jpg`) -> `IMG_61` -> `a` - `14:08:11` (`image_03.jpg`) -> `IMG_6466` -> `df` - `14:11:36` (`image_19.jpg`) -> `IMG_61` -> `a` - `14:13:09` (`image_01.jpg`) -> `IMG_6365` -> `ce` - `14:18:44` (`image_12.jpg`) -> `IMG_7b` -> `{` - `14:21:03` (`image_08.jpg`) -> `IMG_7469` -> `ti` - `14:24:58` (`image_20.jpg`) -> `IMG_6d` -> `m` - `14:29:12` (`image_05.jpg`) -> `IMG_696e` -> `in` - `14:31:47` (`image_16.jpg`) -> `IMG_67` -> `g` - `14:35:20` (`image_02.jpg`) -> `IMG_2d69` -> `-i` - `14:39:06` (`image_18.jpg`) -> `IMG_73` -> `s` - `14:42:55` (`image_09.jpg`) -> `IMG_2d65` -> `-e` - `14:46:13` (`image_13.jpg`) -> `IMG_76` -> `v` - `14:51:38` (`image_04.jpg`) -> `IMG_6572` -> `er` - `14:55:04` (`image_15.jpg`) -> `IMG_79` -> `y` - `14:59:27` (`image_10.jpg`) -> `IMG_7468` -> `th` - `15:03:10` (`image_06.jpg`) -> `IMG_69` -> `i` - `15:07:42` (`image_17.jpg`) -> `IMG_6e67` -> `ng` - `15:12:29` (`image_11.jpg`) -> `IMG_7d` -> `}`
2. Concatenate the decoded ASCII segments: `deadface{timing-is-everything}`
