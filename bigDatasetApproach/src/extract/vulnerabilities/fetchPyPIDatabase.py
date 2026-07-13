
import json 
import os
import requests
import glob
import os
import re
import pandas
import hashlib
from pathlib import Path


import json
import mysql.connector
from zipfile import ZipFile
from itertools import count
import pandas as pd
from itertools import batched
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet,Specifier,InvalidSpecifier
from packaging.requirements import Requirement



conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)
basepath = os.path.dirname(__file__)

DATA_DIRECTORY = "initial_data"
OSV_DATA = "all"
TEST_DATA = "test"

ALL_OSV_DATA = os.path.abspath(os.path.join(basepath, '../..', DATA_DIRECTORY,TEST_DATA))

ECOSYSTEM = 'PyPI'
URL = "https://api.osv.dev/v1/query"
            
def find_vulnerabilities(name):
    parameters = { "package": { "name": name, "ecosystem": ECOSYSTEM}}
    response = requests.post(URL,json=parameters)
    if response.request == 400:
        return None
    else:
        data = response.json()
        if not data:
            return
        vulnerability = data['vulns']
        return vulnerability
    
def read_OSV_file(directory):
    dir_path = Path(directory)
    for file in dir_path.iterdir():
        if file.is_file():
            with open(file,"r") as OSV:
                vulnerability = json.load(OSV)
                affected = vulnerability.get("affected",[])
                for i in affected:
                    name = i.get("package")["name"]    
                    print(name)  
# read_OSV_file(ALL_OSV_DATA)
value = None
try:
    value = SpecifierSet("<1.6.0-beta.4.0.20240610221955-50774cd97099")
except InvalidSpecifier as e:
    value = None
    
print(value)      
