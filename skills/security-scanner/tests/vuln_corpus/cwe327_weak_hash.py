import hashlib
def f(p):
    return hashlib.md5(p.encode()).hexdigest()
