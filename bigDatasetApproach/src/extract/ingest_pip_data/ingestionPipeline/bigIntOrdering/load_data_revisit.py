

import glob
import os
import re
import hashlib

import json
import mysql.connector
from zipfile import ZipFile
from itertools import batched
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
from itertools import batched
import findingRanges as r

conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)
basepath = os.path.dirname(__file__)

DATA_DIRECTORY = "initial_data"
PYPI_DATA_ZIP = "pypi_metadata.zip"
PYPI_DATA_PATH = os.path.abspath(os.path.join(basepath, '../..', DATA_DIRECTORY,PYPI_DATA_ZIP))
print(PYPI_DATA_PATH)
CSV_DIRECTORY_PATH = os.path.abspath(os.path.join(basepath, "csv"))
BATCH_SIZE = 5000

package_query = """
                INSERT IGNORE INTO package_metadata_v2(name)
                VALUES (%s)
                ON DUPLICATE KEY UPDATE id=id;
                """
requirements_query = """
                INSERT IGNORE INTO package_requirements_v2(package_version_id,requirement)
                VALUES (%(package_version_id)s, %(req)s) 
"""

##from PEP: https://peps.python.org/pep-0503/#normalized-names

def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()
    
def read_json_file(zip,jsonFile,packages_version_map):
    seen_packages = set()
    with zip.open(jsonFile,'r') as file:
        for line_batch in batched(file, 1000):
            for line in line_batch:
                json_clean = line.strip()
                data = json.loads(json_clean)
                name = normalize(data.get("name"))
                try:
                    v = parse(data.get("version"))
                except Exception as e:
                    continue                
                if name not in seen_packages:
                   seen_packages.add((name,)) 
                if name not in packages_version_map:
                    packages_version_map[name] = set()
                packages_version_map[name].add(v)                          
    insert_package_names(seen_packages)
    print(f"FINISHED WITH FILE {jsonFile}")

def insert_package_names(seen_packages):
    print("instering packages")
    for chunk in batched(list(seen_packages), 1000):
        cursor.executemany(package_query,chunk)
    conn.commit() 

def handle_versions(version: Version):
    MAX_UNSIGNED_BIGINT = 18446744073709551615
    try:
        major = int(version.major)
        minor = int(version.minor)
        micro = int(version.micro)
        
        if major > MAX_UNSIGNED_BIGINT:
            major = MAX_UNSIGNED_BIGINT
        if minor > MAX_UNSIGNED_BIGINT:
            minor = MAX_UNSIGNED_BIGINT
        if micro > MAX_UNSIGNED_BIGINT:
            micro = MAX_UNSIGNED_BIGINT
        return [str(version),major,minor,micro]
    except Exception as e:
        return []

def structure_version_dict(versions_dict):
    print("inserting versions")
    versions_args = []
    for name,versions_list in versions_dict.items():
        sorted_version = sorted(versions_list)
        for i in range(len(sorted_version)):
            v = sorted_version[i]
            version = handle_versions(v)
            if len(version) <=0:
                continue
            versions_args.append(
                {
                "name" : name,
                "string_version": version[0],
                "major":version[1],
                "minor":version[2],
                "micro":version[3],
                "sequence_order": i
                }
    )
    return versions_args

def upsert_versions(versions_dict,conn):
    if len(versions_dict) <=0:
        return 
    cursor = conn.cursor(buffered=True)
    sql_query = """
    INSERT INTO package_versions_v2(package_name_id, string_version, major, minor, micro,sequence_order)
    SELECT p.id, %(string_version)s,%(major)s, %(minor)s,%(micro)s,%(sequence_order)s
    FROM package_metadata_v2 p
    WHERE p.name = %(name)s
    ON DUPLICATE KEY UPDATE package_versions_v2.id=package_versions_v2.id;
    """
    versions_args = structure_version_dict(versions_dict)
    for chunk in batched(versions_args, 1000):
        cursor.executemany(sql_query,chunk) 
        conn.commit() 

def openZipFile(path):
    packages_version_map = dict()
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                read_json_file(zip,i,packages_version_map)
    print(len(packages_version_map))
    upsert_versions(packages_version_map,conn)    
    cursor.close()
    conn.close()
    print("FINISHED LOADING ALL DATA :)-----")  
             
openZipFile(PYPI_DATA_ZIP)

# read_json_file("file-name-000000000000.json")





            
        
        