from lxml import etree
from flask import request
def f():
    p = etree.XMLParser(resolve_entities=True)
    return etree.fromstring(request.data, p)
