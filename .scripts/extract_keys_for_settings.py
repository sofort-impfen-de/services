import copy
import yaml
import os
import re

envs = ["dev", "test"]
script_dir = os.path.dirname(os.path.abspath(__file__))
settings_dir = os.path.join(os.path.dirname(script_dir), "settings/{env}")
certificate_dir = os.path.join(os.path.dirname(script_dir), "settings/{env}/certs")

def enumerate_files(dir, extensions=['.pub', '.key'], exclude=set([])):
    for file in os.listdir(dir):
        path = os.path.join(dir, file)
        if file.startswith('.'):
            continue
        if os.path.isdir(path) and file not in exclude:
            for path in enumerate_files(path):
                yield path
        else:
            for extension in extensions:
                if file.endswith(extension):
                    yield path

if __name__ == '__main__':
    for env in envs:
        keys = {}
        dir = certificate_dir.format(env=env)
        for file in os.listdir(dir):
            m = re.match(r"^(encrypt|sign)-([a-z]*)\.(pub|key)$", file, re.I)
            if m:
                with open(os.path.join(dir, file)) as input:
                    c = input.read()
                purpose, name, type = m.groups()

                if not name in keys:
                    keys[name] = {
                        'name': name,
                        'type': 'ecdh' if purpose == 'encrypt' else 'ecdsa',
                        'purposes' : ['verify', 'sign'] if purpose == 'sign' else ['deriveKey'],
                        'format': 'spki-pkcs8',
                        'params': {
                            'curve': 'p-256',
                        },
                    }
                key = keys[name]

                if type == 'pub':
                    km = re.match(r"^-----BEGIN PUBLIC KEY-----\n(.*)\n-----END PUBLIC KEY-----\s*$", c, re.DOTALL | re.I)
                    key['public_key'] = km.groups()[0].replace("\n", "")
                elif type == 'key':
                    km = re.match(r"^-----BEGIN EC PRIVATE KEY-----\n(.*)\n-----END EC PRIVATE KEY-----\s*$", c, re.DOTALL | re.I)
                    key['private_key'] = km.groups()[0].replace("\n", "")
        signing_keys = [copy.deepcopy(key) for key in list(keys.values())]
        appointments_keys = [copy.deepcopy(key) for key in list(keys.values())]
        for appointments_key in appointments_keys:
            del appointments_key['private_key']
        settings = {
            'signing': {
                'keys': signing_keys
            },
            'appointments': {
                'keys' : appointments_keys,
            }
        }
        env_settings_dir = settings_dir.format(env=env)
        with open(os.path.join(env_settings_dir, "002_certs.yml"), "w") as output:
            output.write("# this is an auto-generated file, do not edit!\n")
            output.write(yaml.dump(settings))
