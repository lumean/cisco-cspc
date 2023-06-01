import json
import os
import sys

base_dir = os.path.join(os.path.dirname(__file__), "..")
sys.path.append(base_dir)
from src.cspc_api.cspc_api import CspcApi

test_xml = os.path.join(os.path.dirname(__file__), "example.xml")

expected_json = os.path.join(os.path.dirname(__file__), "example.json")

with open(test_xml, "r", encoding="utf-8") as f:
    xml = f.read()

with open(expected_json, "r", encoding="utf-8") as f:
    my_json = f.read()

mydict = CspcApi.response_as_dict(xml)

# print(json.dumps(mydict, indent=2))

assert mydict == json.loads(my_json)
