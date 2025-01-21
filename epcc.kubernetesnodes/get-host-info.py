#!/usr/bin/env python3
import pprint
import requests

HOST_NAME = "localhost"
SITE_NAME = "pan_cr4eidf"
API_URL = f"http://{HOST_NAME}/{SITE_NAME}/check_mk/api/1.0"

USERNAME = "cmkadmin"
PASSWORD = "attack-seed-stubborn-mature"

session = requests.session()
session.headers['Authorization'] = f"Bearer {USERNAME} {PASSWORD}"
session.headers['Accept'] = 'application/json'

resp = session.get(
    f"{API_URL}/objects/host_config/eidf-k8s-gpu06",
    params={  # goes into query string
        "effective_attributes": False,  # Show all effective attributes on hosts, not just the attributes which were set on this host specifically.
    },
)
if resp.status_code == 200:
    pprint.pprint(resp.json())
elif resp.status_code == 204:
    print("Done")
else:
    raise RuntimeError(pprint.pformat(resp.json()))
