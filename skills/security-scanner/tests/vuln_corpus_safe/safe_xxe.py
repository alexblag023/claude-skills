from lxml import etree
from flask import request
def f():
    p = etree.XMLParser(resolve_entities=False, no_network=True)
    return etree.fromstring(request.data, p)
