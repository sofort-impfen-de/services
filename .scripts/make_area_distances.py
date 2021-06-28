import secrets
import base64
import json
import gzip
import sys
import os

distances_basename = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/distances{suffix}.{ext}')

def main():
    with gzip.open(distances_basename.format(ext='csv.gz', suffix=''), 'rt') as input:
        lines = input.read().split("\n")
    values = [l.split(",") for l in lines if l.split()]
    distances = {}
    for i, v in enumerate(values):
        af, at = v[0][:2], v[1][:2]
        if af == at:
            continue
        if not af in distances:
            distances[af] = {}
        if not at in distances[af]:
            distances[af][at] = 0.0
        d = float(v[2])
        if distances[af][at] == 0.0 or d < distances[af][at]:
            distances[af][at] = d
    distances_list = []
    for af, vs in distances.items():
        for at, d in vs.items():
            distances_list.append({
                'from': af,
                'to': at,
                'distance': d,
                })
    with open(distances_basename.format(suffix='-areas', ext='json'), 'w') as output:
        json.dump({'distances' : distances_list, 'type': 'zipArea'}, output, indent=2)
if __name__ == '__main__':
    main()
