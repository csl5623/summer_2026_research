

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
    
def read_json_file(zip,jsonFile):
    seen_packages = set()
    seen_versions = set()
            
    with zip.open(jsonFile,'r') as file:
    # with open(jsonFile,'r') as file:
        for line_batch in batched(file, 1000):
            versions_map = dict()
            packages_list = list()
            versions = list()   
            requirements_dict = dict()   
            req_list = list()
            batch_versions = set()
            for line in line_batch:
                json_clean = line.strip()
                data = json.loads(json_clean)
                name = normalize(data.get("name"))
                try:
                    v = parse(data.get("version"))
                except Exception as e:
                    continue
                
                req = data.get("dependencies",[])
                if name not in seen_packages:
                    seen_packages.add(name)
                    packages_list.append((name,))
                    
                if (name,v) not in seen_versions:
                    seen_versions.add((name,v))
                    batch_versions.add((name,v))
                    
                    if name not in versions_map:
                        versions_map[name] = []
                    versions_map[name].append(str(v))
                    
                    if (name,str(v)) not in requirements_dict:
                        requirements_dict[(name,str(v))] = req
                                
            cursor.executemany(package_query, packages_list)
            conn.commit()
            upsert_versions(versions_map,conn)
            upsert_req(requirements_dict,conn)
            packages_list.clear()
            versions.clear()
            req_list.clear()
            
    print(f"FINISHED WITH FILE {jsonFile}")


def handle_versions(version):
    MAX_UNSIGNED_BIGINT = 18446744073709551615
    try:
        v = parse(version)
        major = int(v.major)
        minor = int(v.minor)
        micro = int(v.micro)
        
        if major > MAX_UNSIGNED_BIGINT:
            major = MAX_UNSIGNED_BIGINT
        if minor > MAX_UNSIGNED_BIGINT:
            minor = MAX_UNSIGNED_BIGINT
        if micro > MAX_UNSIGNED_BIGINT:
            micro = MAX_UNSIGNED_BIGINT
        return [str(v),major,minor,micro]
    except Exception as e:
        return []

 
def upsert_req(req_dict,conn):
    if len(req_dict) <=0:
        return 
    cursor = conn.cursor(buffered=True)
    sql_query = """
    INSERT INTO package_requirements_v2(package_version_id, requirement)
    SELECT v.id, %(req)s
    FROM package_versions_v2 v
    JOIN package_metadata_v2 p ON p.id = v.package_id
    WHERE p.name = %(name)s AND v.string_version = %(version)s
    ON DUPLICATE KEY UPDATE package_requirements_v2.id=package_requirements_v2.id;
    """
    batch_args = []
    for (name,version) in req_dict:
        req = req_dict[(name,version)] 
        for r in req:
            batch_args.append({"req":r,"name":name,"version":version})
    cursor.executemany(sql_query,batch_args) 
    conn.commit()
    
def upsert_versions(versions_dict,conn):
    if len(versions_dict) <=0:
        return 
    cursor = conn.cursor(buffered=True)
    sql_query = """INSERT INTO package_versions_v2(package_id, string_version, major, minor, micro)
    SELECT p.id, %(string_version)s,%(major)s, %(minor)s,%(micro)s
    FROM package_metadata_v2 p
    WHERE p.name = %(name)s
    ON DUPLICATE KEY UPDATE package_versions_v2.id=package_versions_v2.id;
    """
    
    versions_args = []
    for name in versions_dict:
        versions_list = versions_dict[name]
        for v in versions_list:
            version = handle_versions(v)
            if len(version) <=0:
                continue
            versions_args.append(
                {
                "name" : name,
                "string_version": version[0],
                "major":version[1],
                "minor":version[2],
                "micro":version[3]
                }
            )
    cursor.executemany(sql_query,versions_args) 
    conn.commit()

def openZipFile(path):
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                read_json_file(zip,i)
        cursor.close()
        conn.close()
    print("FINISHED LOADING ALL DATA :)-----")  
             
openZipFile(PYPI_DATA_ZIP)

# read_json_file("file-name-000000000000.json")





            
        
        