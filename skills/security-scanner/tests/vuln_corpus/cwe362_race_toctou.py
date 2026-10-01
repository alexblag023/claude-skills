import os
def f(p):
    if os.path.exists(p):
        return open(p).read()
