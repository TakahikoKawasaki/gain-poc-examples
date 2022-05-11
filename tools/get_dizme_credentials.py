"""
This tool can be used to register a client with Dizme. Make sure to adapt the data in the request to your needs.
"""

import requests

print(
    requests.post(
        "https://gain-oidc-cl.dizme.io/v2.0/intra-backoffice/client",
        data={
            "redirect_url": "http://localhost:3000/yes/oidccb",
            "scope": "openid",
            "domain": "example.com",
            "img_url": "https://upload.wikimedia.org/wikipedia/commons/8/8a/Banana-Single.jpg",
        },
    ).text
)

