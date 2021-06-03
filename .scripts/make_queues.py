import secrets
import base64
import json
import sys
import os

areas = ["01", "02", "03", "04", "06", "07", "08", "09", "10", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33", "34", "35", "36", "37", "38", "39", "40", "41", "42", "44", "45", "46", "47", "48", "49", "50", "51", "52", "53", "54", "55", "56", "57", "58", "59", "60", "61", "63", "64", "65", "66", "67", "68", "69", "70", "71", "72", "73", "74", "75", "76", "77", "78", "79", "80", "81", "82", "83", "84", "85", "86", "87", "88", "89", "90", "91", "92", "93", "94", "95", "96", "97", "98", "99"]

queues_filename = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'settings/{env}/queues.json')

def main():
	key_filename = sys.argv[1]
	with open(key_filename) as input:
		key = json.load(input)
	queues = []
	for area in areas:
		queues.append({
			'encryptedPrivateKey' : key['encryptedPrivateKey'],
			'publicKey' : key['publicKey'],
			'type': 'zipArea',
			'name': area,
			'id': base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
			'data': {
				'zipArea': area,
			}
			})
	for env in ['dev', 'test']:
		with open(queues_filename.format(env=env), 'w') as output:
			json.dump({'queues' : queues}, output, indent=2)

if __name__ == '__main__':
	main()