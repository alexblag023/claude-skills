import requests
def f():
    return requests.get('https://x.example', verify=False).text
