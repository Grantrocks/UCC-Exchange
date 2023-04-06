import requests
import json
import time
while True:
    with open("database.json") as f:
        database=json.load(f)