
from itertools import batched
import json
import os
import re

import mysql.connector
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
import hashlib
from zipfile import ZipFile
import summer_2026_research.bigDatasetApproach.src.extract.ingest_pip_data.fix_ingestion_pipeline.bigIntOrdering.findingRanges as ranges


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

def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()


insert_dependency = """
    INSERT  INTO dependencies_v2(parent_version_id, child_version_id)
    VALUES (%(parent_id)s,%(child_id)s)
    ON DUPLICATE KEY UPDATE dependencies_v2.parent_version_id=dependencies_v2.parent_version_id
"""

def store_dependencies(result,conn,packages_versions):
    batch_list = []
    SAFE_CHUNK_SIZE = 5000
    insert_cursor = conn.cursor(buffered=True)
    for row in result:  
        if len(batch_list) >= SAFE_CHUNK_SIZE:
           print(f"Flushing safe chunk of {len(batch_list)}rows")
           insert_cursor.executemany(insert_dependency, batch_list)
           conn.commit() 
           batch_list.clear()
        parent_version_id, requirement = row
        if requirement:
            try:
                req = Requirement(requirement)  
                req_name = normalize(req.name)
                specifier = req.specifier
                all_versions = packages_versions[req_name]
                dep_versions = list(specifier.filter(all_versions))
                for i in dep_versions:
                    try:
                        v = str(parse(i))
                    except Exception as e:
                        print(e)
                        continue
                    batch_list.append({"dep_name":req_name,"parent_version_id":parent_version_id,"version":v})
            except Exception:
                continue
    insert_cursor.close()
def fetch_database(batch_size):
        query = f"""
    SELECT package_version_id, requirement 
    FROM package_requirements_v2;
    """
        try:
            conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                                    database='vulnerability_tracking')
            cur = conn.cursor(buffered=True)
           
            print("executing query")
            cur.execute(query)  
            print("query executed")
            packages_versions = get_all_package_versions(conn)  
            while True:
                    rows = cur.fetchmany(size=batch_size)
                    if not rows:
                        break
                    print(f"Processing {len(rows)}")
                    store_dependencies(rows,conn,packages_versions)

        except Exception as e:
            print("errror")
            print(e)
        if cur:
            cur.close()
        if conn:
            conn.close()
# fetch_database(batch_size=5000)
    
def get_all_package_versions(conn):
    local_cursor = conn.cursor(buffered=True)
    query_fetch = f"""
        select v.id, p.name, v.string_version as version from package_versions_v2 v
        JOIN package_metadata_v2 p ON p.id = v.package_id
    """
    local_cursor.execute(query_fetch)
    query_result = local_cursor.fetchall()
    
    packages_versions_map = dict()
    packages_versions_id_map = dict()
    for row in query_result:
        v_id, name,version, = row
        if name not in packages_versions_map:
            packages_versions_map[name] = []
        packages_versions_map[name].append(version)
        
        if (name,version) not in packages_versions_id_map:
            packages_versions_id_map[(name,version)] = v_id 
    local_cursor.close()
    return packages_versions_map,packages_versions_id_map

# def read_json_file(jsonFile,package_versions_map,packages_versions_id_map):
def read_json_file(jsonFile):
    # with zip.open(jsonFile,'r') as file: 
    with open(jsonFile,"r") as file:
        for line_batch in batched(file, 1000):
            batch_list = []
            for line in line_batch:
                json_clean = line.strip()
                data = json.loads(json_clean)
                p_name = normalize(data.get("name"))
                try:
                    p_v = str(parse(data.get("version")))
                except Exception as e:
                    continue 
                # if (p_name,p_v) in packages_versions_id_map:
                #     parent_id = packages_versions_id_map[(p_name,p_v)]
                dependencies = data.get("dependencies",[])
                for req in dependencies:
                    try:
                        r = Requirement(req)
                    except Exception as e:
                        continue
                    spec = str(r.specifier)
                    range = ranges.get_ranges(spec)
                    print(range)
            #             name = normalize(r.name)
            #             specifier = r.specifier
            #             if name in package_versions_map:
            #                 all_versions = package_versions_map[name]
            #                 dep_versions = sorted(list(specifier.filter(all_versions)))
            #                 for i in dep_versions:
            #                     if (name,i) in packages_versions_id_map:
            #                         child_id = packages_versions_id_map[(name,i)]
            #                         batch_list.append({"child_id":child_id,"parent_id":parent_id})  
            # print(len(batch_list))
            # for chunk in batched(batch_list, 5000):
            #     cursor.executemany(insert_dependency,chunk)
            #     conn.commit()    
    print(f"FINISHED WITH FILE {jsonFile}")

def test_single_json():
    # package_versions_map, package_id_map = get_all_package_versions(conn)
    read_json_file("file-name-000000000000.json")

test_single_json()

def find_dependencies_ranges(rows,conn):
    cursor = conn.cursor(buffered=True)
    sql_query = """
    INSERT INTO package_dependencies(package_version_id,package_id,specifier)
    SELECT %(version_id)s,p.id,%(specifier)s
    from package_metadata_v2 p
    WHERE p.name = %(dep_name)s
    """
    dep_list = []
    for package_version,req in rows:
        r = Requirement(req)
        name = normalize(r.name)
        specifier = str(r.specifier)
        dep_list.append({
            "version_id":package_version,
            "specifier":specifier,
            "dep_name":name
        })
    cursor.executemany(sql_query,dep_list) 
    conn.commit()

def openZipFile(path):
    package_versions_map, package_id_map = get_all_package_versions()
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                read_json_file(zip,i,package_versions_map,package_id_map)
        cursor.close()
        conn.close()
    print("FINISHED LOADING ALL DATA :)-----")  
    