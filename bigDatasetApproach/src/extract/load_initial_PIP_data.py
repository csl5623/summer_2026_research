

import glob
import os
import re
import pandas
import hashlib

import json
import mysql.connector
from zipfile import ZipFile
from itertools import count
import pandas as pd
from itertools import batched
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement



conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)
basepath = os.path.dirname(__file__)

DATA_DIRECTORY = "initial_data"
PYPI_DATA_ZIP = "pypi_metadata.zip"
PYPI_DATA_PATH = os.path.abspath(os.path.join(basepath, '..', DATA_DIRECTORY,PYPI_DATA_ZIP))
CSV_DIRECTORY_PATH = os.path.abspath(os.path.join(basepath, "csv"))
BATCH_SIZE = 5000

package_query = """
                INSERT IGNORE INTO package_metadata(id,name)
                VALUES (%s,%s)
                """
versions_query = """
    INSERT IGNORE INTO package_versions(id, package_id, string_version, major, minor, micro)
    VALUES (%(id)s, %(package_id)s, %(version)s, %(major)s, %(minor)s, %(micro)s)
"""
requirements_query = """
                INSERT IGNORE INTO package_requirements(package_version_id,requirement)
                VALUES (%(package_version_id)s , %(req)s) 
"""

##from PEP: https://peps.python.org/pep-0503/#normalized-names
def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def generate_id(string):
    hash_bytes = hashlib.sha256(string.encode('utf-8')).hexdigest()
    return hash_bytes

def handle_versions(version):
    try:
        v = parse(version)
        major = v.major
        minor = v.minor
        micro = v.micro
        return [int(major),int(minor),int(micro)]
    except Exception as e:
        return []
    
def read_json_file(jsonFile):
    seen_packages = set()
    packages_list = list()
    seen_versions = set()
    versions = list()   
    requirements = list()
    
    with open(jsonFile,'r') as file:
        for line in file:
            json_clean = line.strip()
            data = json.loads(json_clean)
            name = normalize(data.get("name"))
            v = data.get("version")
            version = handle_versions(v)
            req = data.get("dependencies",[])
            
            if name not in seen_packages:
                seen_packages.add(name)
                id = generate_id(name)
                packages_list.append((id,name,))
            
            if (name,v) not in seen_versions:
                seen_versions.add((name,v))
                if version:
                    v_id = generate_id(f'{name}|{v}')
                    versions.append({
                        "id" : v_id,
                        "package_id" : generate_id(name),
                        "version": v,
                        "major":version[0],
                        "minor":version[1],
                        "micro":version[2]
                    })
                    
                    if len(req) <= 0:
                        requirements.append({"package_version_id":v_id,"req":None})
                    else:
                        for d in req:
                            requirements.append({"package_version_id":v_id,"req":d})
                            
            if len(packages_list) >= BATCH_SIZE or len(versions)>=BATCH_SIZE or len(requirements) >=BATCH_SIZE:
                cursor.executemany(package_query, packages_list)
                conn.commit()
                packages_list.clear()
                cursor.executemany(versions_query, versions)
                conn.commit()
                versions.clear()
                cursor.executemany(requirements_query, requirements)
                conn.commit()
                requirements.clear()
    
    print("finished loop")
    if packages_list:
        cursor.executemany(package_query, packages_list)
        conn.commit()
        packages_list.clear()
    print("finished remaining packages")        
    if versions:
        cursor.executemany(versions_query, versions)
        conn.commit()
        versions.clear()
    print("finished remaining versions")  
    if requirements:
        cursor.executemany(requirements_query, requirements)
        conn.commit()
        requirements.clear()
    
    print(f"FINISHED WITH FILE {jsonFile}")

          

def openZipFile(path):
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                read_json_file(zip,i)
                
# openZipFile(PYPI_DATA_PATH)

read_json_file("file-name-000000000000.json")
