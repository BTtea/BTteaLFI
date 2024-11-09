from base64 import b64encode

# page=/etc/passwd  =>  page=L2V0Yy9wYXNzd2Q=

def tamper(payload:str):
    if payload:
        payload=b64encode(payload.encode()).decode()
    return payload
