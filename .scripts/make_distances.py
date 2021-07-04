import secrets
import base64
import json
import gzip
import sys
import os

distances_basename = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/distances.{ext}')

def main():
	with gzip.open(distances_basename.format(ext='csv.gz'), 'rt') as input:
		lines = input.read().split("\n")
	values = [l.split(",") for l in lines if l.split()]
	distances = []
	for i, v in enumerate(values):
		distances.append({
			'from': v[0],
			'to': v[1],
			'distance': float(v[2]),
			})
	with open(distances_basename.format(ext='json'), 'w') as output:
		json.dump({'distances' : distances, 'type': 'zipCode'}, output, indent=2)

if __name__ == '__main__':
	main()