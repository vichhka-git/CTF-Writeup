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
    default_root = here / 'files' if (here / 'files' / 'handout_file_1.txt').exists() else here
    parser.add_argument('challenge', nargs='?', type=Path, default=default_root)
    parser.add_argument('--out', type=Path)
    parser.add_argument('--glyphs', type=Path, help='Reviewed visual transcription indexed by condition constant')
    args = parser.parse_args()
    if args.out is None:
        args.out = here / 'work' / 'artifacts' / 'reproduction'
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
