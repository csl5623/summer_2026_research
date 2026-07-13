
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
import findingRanges as ranges

conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)
basepath = os.path.dirname(__file__)
PYPI_DATA_ZIP = "pypi_metadata.zip"


def get_all_package_versions(conn):
    local_cursor = conn.cursor(buffered=True)
    query_fetch = f"""
        select v.id,p.name, v.string_version, v.sequence_order from package_versions_v2 v
        JOIN package_metadata_v2 p ON p.id = v.package_name_id
    """
    local_cursor.execute(query_fetch)
    query_result = local_cursor.fetchall()
    packages_versions_map = dict()
    versions_id_map = dict()
    for row in query_result:
        v_id, name,version,sequence_number, = row
        if name not in packages_versions_map:
            packages_versions_map[name] = list()
        packages_versions_map[name].append(Version(version))
        
        if (name,version) not in versions_id_map:
            versions_id_map[(name,version)] = (v_id,sequence_number)
    
    return packages_versions_map,versions_id_map


def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()
    
def read_json_file(zip,jsonFile,packages_versions_map,versions_id_map,conn,name_versions_set):
    with zip.open(jsonFile,'r') as file:
        for line_batch in batched(file, 1000):
            batch_list = list()
            for line in line_batch:
                json_clean = line.strip()
                data = json.loads(json_clean)
                name = normalize(data.get("name"))
                try:
                    v = parse(data.get("version"))
                except Exception as e:
                    continue  
                dependencies = data.get("dependencies",[])
                if (name,v) not in name_versions_set:
                    name_versions_set.add((name,v))
                    for req in dependencies:
                        try:
                            r = Requirement(req)
                        except Exception as e:
                            continue
                        parent_version_id = None
                        if (name,str(v)) in versions_id_map:
                            parent_version_id = versions_id_map[(name,str(v))][0]
                        if parent_version_id:
                            output = process_requirement_ranges(r,packages_versions_map,parent_version_id,versions_id_map)  
                            batch_list.extend(output)
                else:
                    print("version already added")
            print("inserting into database")
            upsert_dependencies(batch_list,conn)
    print(f"FINISHED WITH FILE {jsonFile}")

def upsert_dependencies(batch_list,conn):
    if len(batch_list) <=0:
        return 
    cursor = conn.cursor(buffered=True)
    sql_query = """
    INSERT INTO dependencies_v2(dependency_package_name_id, parent_version_id, specifier_string,lower_bound_order_number,upper_bound_order_number)
    SELECT p.id, %(parent_version_id)s, %(spec)s,%(lower_bound)s,%(upper_bound)s
    FROM package_metadata_v2 p
    WHERE p.name = %(child_package_name)s
    """
    print("INSERTING DEPENDENCIES-------------")
    for chunk in batched(batch_list, 1000):
        cursor.executemany(sql_query,chunk) 
    conn.commit() 
    cursor.close()
           
def process_requirement_ranges(r:Requirement,packages_versions_map,parent_version_id,versions_id_map):
    spec = r.specifier
    name = normalize(r.name)
    
    if name not in packages_versions_map:
        return [{"parent_version_id":parent_version_id,
                "child_package_name":name,
                "lower_bound":None,
                "upper_bound":None,
                "spec":None
        }]            
    if not r.specifier:
       return [{"parent_version_id":parent_version_id,
                "child_package_name":name,
                "lower_bound":None,
                "upper_bound":None,
                "spec":None
    }]
       
    versions = sorted(packages_versions_map[name])
    
    rgs = ranges.get_ranges(spec)
    ranges_list = list()
    for range in rgs:
        lower_bound,upper_bound = range
        lower_version,lower_is_inclusive = lower_bound["version"], lower_bound["inclusive"]
        upper_version,upper_is_inclusive = upper_bound["version"], upper_bound["inclusive"]
        lower_bound_order_number = None
        upper_bound_order_number = None
        if lower_version:
            lower_bound_v = find_closest_version_lower_bound(versions,lower_version,lower_is_inclusive)
            if(name,lower_bound_v) in versions_id_map:
                lower_bound_order_number = versions_id_map[(name,lower_bound_v)][1]
        if upper_version:
            upper_bound_v = find_closes_version_upper_bound(versions,upper_version,upper_is_inclusive)  
            if(name,upper_bound_v) in versions_id_map:
                upper_bound_order_number = versions_id_map[(name,upper_bound_v)][1] 
        ranges_list.append({
                    "parent_version_id":parent_version_id,
                    "child_package_name":name,
                    "lower_bound":lower_bound_order_number,
                    "upper_bound":upper_bound_order_number,
                    "spec":str(spec)
        })
    return ranges_list

def find_closest_version_lower_bound(sorted_versions,lower_version,lower_is_inclusive):
    version = None
    if not lower_version:
        return None
    
    for i in range(len(sorted_versions)):
        if lower_is_inclusive:
            if sorted_versions[i] >= lower_version:
                    version = sorted_versions[i]
                    break
        else:
            if sorted_versions[i] > lower_version:
                version = sorted_versions[i]
                break
    if not version:
        version = sorted_versions[-1]
    return str(version)

def find_closes_version_upper_bound(sorted_versions,upper_version,upper_is_inclusive):
    version = None
    if not upper_version:
        return None
    for i in range(len(sorted_versions) - 1, -1, -1):
        if upper_is_inclusive:    
            if sorted_versions[i] <= upper_version:
                version = sorted_versions[i]
                break
        else:
            if sorted_versions[i] < upper_version:
                version = sorted_versions[i]
                break   
    if not version:
        version = sorted_versions[0]
    return str(version)
                
def openZipFile(path):
    packages_versions_map,versions_id_map = get_all_package_versions(conn)
    name_versions_set = set()
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                read_json_file(zip,i,packages_versions_map,versions_id_map,conn,name_versions_set)
    name_versions_set.clear()
    cursor.close()
    conn.close()
    print("FINISHED LOADING ALL DATA :)-----")  
             
openZipFile(PYPI_DATA_ZIP)
               

    