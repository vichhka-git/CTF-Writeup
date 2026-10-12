# FortID CTF 2026 Writeup: Tangled

- **Category:** Misc
- **Challenge author:** laragrr
- **Points / Solves:** 362 pts / 8 solves
- **Flag:** `FortID{Wh3n_7h3_8e1ts_b3c0me_5p49hett1_tr41n5_8ec0m3_th3_0n1y_r34s0n4b1e_50lut10n}`

---

## Challenge

> An abandoned factory hides a message within its tangled machinery. Untangle the construction and uncover the secret.

---

## Summary

The two attachments are Factorio blueprint strings. The flag is split between two QR codes and 29 circuit wire drawings, ordered by their circuit condition constants. The mechanism matches the description’s instruction to untangle the construction; this is the likely intended path, without an official solution comparison.

## Solution

### Step 1: Decode the blueprints and QR grids

Remove the leading `0`, base64-decode, then zlib-decompress and parse JSON. Blueprint 1’s841 tiles form a 29×29 grid: landfill is black and foundation is white. This yields:

```text
FortID{Wh3n_7h3_8e1ts_b3c0me
```

Translate blueprint 1 entity centers by `(x+54.5,y−9.5)` and round them to grid cells. XOR their occupied-cell set with blueprint 2’s landfill positions in the 25×25 grid `[-12,12]²`. Its QR payload is:

```text
_5p49hett1_tr41n5_8ec0m3_
```

The script uses `zbarimg --xml` so decoder output delimiters do not become flag bytes.

### Step 2: Untangle the circuit drawings

Treat each wire endpoint as `(entity_number,connector_id)` and find connected components. Keeping connector IDs matters because combinator input and output occupy different positions. There are 29 components. Each contains one distinct simple `control_behavior.circuit_condition.constant`, and these values span 1 through 29. Other decider thresholds belong to the factory circuitry and should not be used as ordering labels.

Plot each component separately in that order, with equal axis scale and increasing y downwards. Circuit connector offsets clarify the shapes of `t`, `b`, and the closing brace. The reviewed visual transcription is:

```text
th3_0n1y_r34s0n4b1e_50lut10n}
```

Position 13 is `s`; position 21 is `5`. Earlier candidates incorrectly used `5` at both positions. The accepted spelling comes from visual reading followed by platform confirmation. The script bundles that reviewed transcription; it does not claim to infer character case automatically. Belt endpoints use animation frame 0, whose small movement does not affect this reading.

Connector research used Wube’s official [generated definitions for 2.0.77](https://raw.githubusercontent.com/wube/factorio-data/2.0.77/core/lualib/circuit-connector-generated-definitions.lua), [Space Age circuit definitions for 2.0.77](https://raw.githubusercontent.com/wube/factorio-data/2.0.77/space-age/prototypes/entity/circuit-network.lua), and [combinator connector positions](https://github.com/wube/factorio-data/blob/master/base/prototypes/entity/combinator-pictures.lua). The first blueprint’s version field identifies 2.0.77.

### Step 3: Reproduce and confirm

Dependencies: Python 3, Pillow, and `zbarimg`. Run from the challenge directory:

```bash
python3 solve.py
```

The script regenerates both QR images, the numbered component image, and component JSON under `work/artifacts/reproduction/`, then prints the flag. The complete script follows:

```python
#!/usr/bin/env python3
"""Decode the QR grids and render the visually transcribed numbered wire glyphs."""
import argparse
import base64
from collections import defaultdict
import json
from pathlib import Path
import subprocess
import xml.etree.ElementTree as ET
import zlib

from PIL import Image, ImageDraw

def blueprint(path):
    raw = path.read_text().strip()
    if not raw.startswith('0'):
        raise ValueError('Unsupported blueprint version marker')
    return json.loads(zlib.decompress(base64.b64decode(raw[1:])))['blueprint']

def qr_payload(grid, output):
    side = len(grid)
    im = Image.new('L', (side + 8, side + 8), 255)
    for y, row in enumerate(grid):
        for x, value in enumerate(row):
            if value:
                im.putpixel((x + 4, y + 4), 0)
    im.resize(((side + 8) * 12, (side + 8) * 12), Image.Resampling.NEAREST).save(output)
    p = subprocess.run(['zbarimg', '--quiet', '--xml', str(output)], capture_output=True, check=True)
    root = ET.fromstring(p.stdout)
    data = [element.text for element in root.iter() if element.tag.endswith('data')]
    if len(data) != 1:
        raise ValueError('Expected exactly one QR payload')
    return data[0]

def components(bp):
    es = {e['entity_number']: e for e in bp['entities']}
    adjacency = defaultdict(set)
    for a, ca, b, cb in bp['wires']:
        adjacency[a, ca].add((b, cb))
        adjacency[b, cb].add((a, ca))
    seen, groups = set(), []
    for start in adjacency:
        if start in seen:
            continue
        pending, nodes = [start], set()
        while pending:
            node = pending.pop()
            if node in nodes:
                continue
            nodes.add(node)
            pending.extend(adjacency[node] - nodes)
        seen.update(nodes)
        ids = {a for a, connector in nodes}
        labels = [es[a].get('control_behavior', {}).get('circuit_condition', {}).get('constant') for a in ids]
        labels = [label for label in labels if label is not None]
        if len(set(labels)) != 1:
            raise ValueError(f'Component has inconsistent simple condition labels: {labels}')
        label = labels[0]
        wires = [w for w in bp['wires'] if (w[0], w[1]) in nodes and (w[2], w[3]) in nodes]
        color = 'red' if start[1] % 2 else 'green'
        groups.append({'index': label, 'color': color, 'nodes': sorted(nodes), 'wires': wires,
                       'entities': [es[a] for a in sorted(ids)]})
    groups.sort(key=lambda g: g['index'])
    if [g['index'] for g in groups] != list(range(1, 30)):
        raise ValueError('Expected condition indices 1 through 29 exactly once')
    return groups

WIRE_TEXT = "th3_0n1y_r34s0n4b1e_50lut10n}"

def anchor(entity, connector):
    name = entity['name']
    direction = entity.get('direction', 0) // 4
    red = connector % 2
    if name == 'biochamber':
        offset = (-32, 29) if red else (-36, 35)
    elif 'inserter' in name:
        variants = [(13,-8),(7.5,-11),(16.5,3.5),(-5.5,-10.5)] if red else [(16,-2.5),(13,-8),(12.5,8),(-11,-9)]
        offset = variants[[2,3,0,1][direction]]
    elif name == 'decider-combinator':
        inputs = [(-8.5,15.5),(-22.5,-18.5),(8.5,-19.5),(23.5,-4)]
        outputs = [(-9,-21.5),(19.5,-17),(9.5,17),(-19,-4)]
        assert connector in (1,3)
        offset = (inputs if connector == 1 else outputs)[direction]
    elif name == 'turbo-transport-belt':
        # Frame0; belt animation moves this endpoint slightly between frames.
        offset = (12.5,-20.5) if red else (20.5,-16)
    elif name == 'passive-provider-chest':
        offset = (11,6.5) if red else (13,13.5)
    elif name == 'display-panel':
        assert direction == 0
        offset = (-11,-17.5) if red else (12,-17.5)
    else:
        raise ValueError(name)
    return tuple(entity['position'][axis] + offset[i]/32 for i,axis in enumerate(('x','y')))

def draw_components(groups, output):
    cols, cell = 6, 240
    im = Image.new('RGB', (cols * cell, 5 * cell), 'white')
    pen = ImageDraw.Draw(im)
    for i, group in enumerate(groups):
        entities = {e['entity_number']: e for e in group['entities']}
        positions = {(eid,port): anchor(entities[eid],port) for eid,port in group['nodes']}
        xs = [v[0] for v in positions.values()]
        ys = [v[1] for v in positions.values()]
        width, height = max(xs) - min(xs), max(ys) - min(ys)
        scale = 175 / max(width, height, 1)
        x0, y0 = (i % cols) * cell, (i // cols) * cell
        def point(eid, port):
            x, y = positions[eid, port]
            return x0 + 120 + (x - (min(xs) + max(xs))/2) * scale, y0 + 135 + (y - (min(ys) + max(ys))/2) * scale
        pen.text((x0 + 15, y0 + 10), f"{group['index']} / {group['color']}", fill='black')
        for a, ca, b, cb in group['wires']:
            pen.line([point(a,ca), point(b,cb)], fill=group['color'], width=3)
    im.save(output)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent
    default_root = here if (here / 'handout_file_1.txt').exists() else here.parent
    parser.add_argument('challenge', nargs='?', type=Path, default=default_root)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--glyphs', type=Path, help='Reviewed visual transcription indexed by condition constant')
    args = parser.parse_args()
    if args.out is None:
        args.out = args.challenge / 'work' / 'artifacts' / 'reproduction'
    args.out.mkdir(parents=True, exist_ok=True)
    b1 = blueprint(args.challenge / 'handout_file_1.txt')
    b2 = blueprint(args.challenge / 'handout_file_2.txt')
    tiles = {(int(t['position']['x']), int(t['position']['y'])): t['name'] for t in b1['tiles']}
    xs, ys = [v[0] for v in tiles], [v[1] for v in tiles]
    first = qr_payload([[tiles[x,y] == 'landfill' for x in range(min(xs), max(xs)+1)]
                        for y in range(min(ys), max(ys)+1)], args.out / 'qr1.png')
    occupied = {(round(e['position']['x'] + 54.5), round(e['position']['y'] - 9.5)) for e in b1['entities']}
    mask = {(int(t['position']['x']), int(t['position']['y'])) for t in b2['tiles']}
    second = qr_payload([[(x,y) in (occupied ^ mask) for x in range(-12,13)] for y in range(-12,13)], args.out / 'qr2.png')
    groups = components(b1)
    (args.out / 'components.json').write_text(json.dumps(groups, indent=2))
    draw_components(groups, args.out / 'components.png')
    print('QR1:', first)
    print('QR2:', second)
    print('Circuit components:', len(groups), 'indexed 1..29; drawing:', args.out / 'components.png')
    last = WIRE_TEXT
    if args.glyphs:
        glyphs = json.loads(args.glyphs.read_text())
        last = ''.join(glyphs[str(g['index'])] for g in groups)
    assert len(last) == len(groups)
    print('Wire transcription (visually reviewed):', last)
    print(first + second + last)

if __name__ == '__main__':
    main()
```

Concatenate the two QR payloads and reviewed wire transcription. Submission with the platform returned:

```text
200 {"kind": "goodFlag", "message": "The flag is correct."}
```

## Flag

```text
FortID{Wh3n_7h3_8e1ts_b3c0me_5p49hett1_tr41n5_8ec0m3_th3_0n1y_r34s0n4b1e_50lut10n}
```

## Lessons

Use circuit conditions as ordering evidence, then inspect the isolated wire geometry. Factory semantics and an earlier guessed “sushi” ending did not explain the 29 drawings. Entity centers can distort letters; connector IDs and offsets preserve their strokes. QR extraction is automatic, while the wire alphabet requires a visual transcription and exact platform verification.
