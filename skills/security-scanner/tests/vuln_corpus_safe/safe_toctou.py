def f(p):
    try:
        return open(p).read()
    except FileNotFoundError:
        return None
