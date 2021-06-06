import secrets
import base64
import codecs
import json
import sys
import os

codes_filename = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data/{actor}-codes-{env}.json')
hexlify = codecs.getencoder('hex')

def main():
	if len(sys.argv) < 3:
		sys.stderr.write("usage: %s [environment] [number of codes]\n")
		sys.exit(-1)
	env = sys.argv[1]
	n = int(sys.argv[2])
	for actor in ['provider', 'user']:
		codes = [hexlify(secrets.token_bytes(16))[0].decode('ascii') for i in range(n)]
		with open(codes_filename.format(env=env, actor=actor), 'w') as output:
			json.dump({'actor': actor, 'codes': codes}, output, indent=2)

if __name__ == '__main__':
	main()