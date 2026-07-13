import hashlib
import os
import re

import mysql.connector
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet,InvalidSpecifier
from packaging.requirements import Requirement
from pathlib import Path
import json 
from datetime import datetime, timezone

query_fetch = f"""
                select name from package_metadata
                """
def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()
                               
def convert_string_to_timestamp(string):
    if string.startswith("0001-01-01"):
        return None
    clean_time_str = string.replace("Z", "+00:00")
    dt_object = datetime.fromisoformat(clean_time_str)
    return dt_object.astimezone(timezone.utc)

def process_vulnerability(vulnerability,conn,dict_package_versions,batch_list,ranges_batch,versions_batch,cve_batch,versions_id_map):    
    CVE_SET = set()
    vuln_id, summary,aliases = vulnerability.get("id"), vulnerability.get("summary"), vulnerability.get("aliases",[])
    modified = vulnerability.get("modified")
    published = vulnerability.get("published")
    
    exists_cursor = conn.cursor(buffered=True)
    
    vulnerability_exists = False
    for alias_id in aliases:
        if alias_id.startswith("CVE-"):
           CVE_SET.add((vuln_id,alias_id))
           continue 
        query = "SELECT EXISTS(SELECT 1 FROM vulnerability WHERE id = %s) AS value_exists"
        exists_cursor.execute(query, (alias_id,))
        result = exists_cursor.fetchone()
        if result[0]:
           vulnerability_exists = True
    exists_cursor.close()
    
    if not vulnerability_exists:
        if vuln_id.startswith("CVE-"):
            print("CVE record found")
        else:
            print("NEW VULN")
            modified_dt_utc = None
            if modified:
                modified_dt_utc = convert_string_to_timestamp(modified)
            
            published_dt_utc = None
            if published:
                published_dt_utc = convert_string_to_timestamp(published)
            batch_list.append((vuln_id,summary,modified_dt_utc,published_dt_utc)) 
            all_ranges,all_version = process_new_vulnerability(vuln_id,vulnerability,dict_package_versions,versions_id_map)
            ranges_batch.extend(all_ranges)
            versions_batch.extend(all_version)
    else:
        print("vulnerability exists")
    cve_batch.extend(list(CVE_SET))
    
    

def insert_CVE(CVE_list,conn):
    cur= conn.cursor(buffered=True)   
    insert_CVE_query = """
    INSERT INTO CVE_v2(vulnerability_id,CVE_ID)
    VALUES (%s , %s) 
    """
    cur.executemany(insert_CVE_query,CVE_list)
    conn.commit()
    cur.close()  
 
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
        
        if (name,Version(version)) not in versions_id_map:
            versions_id_map[(name,Version(version))] = (v_id,sequence_number)
    return packages_versions_map,versions_id_map


def insert_vulnerabilities(batch_list,conn):
    insert_cursor= conn.cursor(buffered=True)
    insert_query = """
    INSERT INTO vulnerability_v2(id, summary, modified, published)
    VALUES(%s, %s, %s, %s)
    ON DUPLICATE KEY UPDATE vulnerability_v2.id = vulnerability_v2.id
    """
    insert_cursor.executemany(insert_query,batch_list)
    conn.commit()
    insert_cursor.close()

def insert_affected_packages(batch_list,conn):
    affected_versions_cursor= conn.cursor(buffered=True)
    insert_affected_packages_query = """
    INSERT IGNORE INTO affected_packages_v2(vulnerability_id,package_version_id)
    VALUES (%s,%s) 
    """
    affected_versions_cursor.executemany(insert_affected_packages_query,batch_list)
    conn.commit()
    affected_versions_cursor.close()

def insert_vulnerability_range(ranges_list,conn):
    vulnerability_range_cursor = conn.cursor(buffered=True)
    insert_vuln_range_query = """
    INSERT INTO vulnerability_range_v2(package_id,vulnerability_id, introduced_version, fixed_version, last_affected_version,introduced_version_order_number,fixed_version_order_number,last_affected_version_order_number)
    SELECT p.id, %(vuln_id)s,%(introduced)s, %(fixed)s, %(last_affected)s, %(introduced_order_number)s, %(fixed_order_number)s,%(last_affected_order_number)s
    FROM package_metadata_v2 p
    WHERE p.name = %(package_name)s
    """
    vulnerability_range_cursor.executemany(insert_vuln_range_query,ranges_list)
    conn.commit()
    vulnerability_range_cursor.close()
        

def process_new_vulnerability(vuln_id,vulnerability,dict_package_versions,versions_id_map):
    print("Affected versions")
    affected = vulnerability.get("affected",[])
    name = None
    package_stored_versions = None
    all_ranges, all_version = list(),list()
    for i in affected:
        n = i.get("package")["name"]
        name = normalize(n)
        
        if name not in dict_package_versions:
           continue 
       
        package_stored_versions = sorted(dict_package_versions[name])
        API_versions_array = set(i.get("versions",[]))
        ranges = i.get("ranges",[])
        if name:
            range_affected_versions,processed_ranges = process_vulnerability_range(name,vuln_id,ranges,package_stored_versions,versions_id_map)
            affected_versions = find_correct_versions_affeccted(name,vuln_id,versions_id_map,API_versions_array,range_affected_versions)
            all_ranges.extend(processed_ranges)
            all_version.extend(affected_versions)
    return all_ranges,all_version
        
         
def find_correct_versions_affeccted(name,vuln_id,versions_id_map,API_versions_array, range_affected_versions):
    convertedAPIRanges = list()
    for i in API_versions_array:
        try:
            v = Version(i)
        except Exception as e:
            continue
        convertedAPIRanges.append(v)
    affected_version = set(convertedAPIRanges) | set(range_affected_versions)
    return map_vulnerability_to_package_version(name,vuln_id,affected_version,versions_id_map)

def map_vulnerability_to_package_version(name,vuln_id,versions,versions_id_map):
    affected_versions = list()
    for version in versions:
        if(name,version) in versions_id_map:
            package_version_id = versions_id_map[(name,version)][0]
            affected_versions.append((vuln_id,package_version_id))
    return affected_versions


##takes a list
def process_vulnerability_range(name,vuln_id,ranges,package_stored_versions,versions_id_map):
    all_affected_versions = list()
    all_ranges = list()
    for range in ranges:
        type = range["type"]
        if type != 'GIT':
            events = range["events"]
            ranges_list = handle_events_object(name,vuln_id,events,package_stored_versions,versions_id_map)           
            affected_versions = find_versions_based_on_range(package_stored_versions,ranges_list)
            all_ranges.extend(ranges_list)
            all_affected_versions.extend(affected_versions)
    
    return all_affected_versions,all_ranges

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
    return version

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
    return version


def mapping_closest_ranges(sorted_versions,version,isIntroduced,isInclusive):
    try:
        v = Version(version)
    except Exception as v:
        return None
    if isIntroduced:
        return find_closest_version_lower_bound(sorted_versions,v,isInclusive)
    else:
        return find_closes_version_upper_bound(sorted_versions,v,isInclusive)

def handle_events_object(name,vuln_id,events,sorted_versions,versions_id_map):
    grouped_ranges = list()
    current_range = None
    for event in events:
        introduced = event.get("introduced",None)
        fixed = event.get("fixed",None)
        last_affected = event.get("last_affected",None)
        
        if introduced:
            closed_introduced = mapping_closest_ranges(sorted_versions,introduced,True,True)
            if current_range is not None:
                grouped_ranges.append(current_range)
            
            value = None
            if (name,closed_introduced) in versions_id_map:
                value = versions_id_map[(name,closed_introduced)][1]
            
            current_range = {
              "vuln_id" : vuln_id,
              "introduced":  introduced,
              "fixed":  None,
              "last_affected": None,
              "introduced_order_number":value,
              "last_affected_order_number":None,
              "fixed_order_number":None,
              "package_name": name
            }

        elif fixed and current_range is not None:
            res =  mapping_closest_ranges(sorted_versions,fixed,False,True)
            
            value = None
            if (name,res) in versions_id_map:
                value = versions_id_map[(name,res)][1]
            
            current_range["fixed_order_number"] = value
            current_range["fixed"] = fixed
            grouped_ranges.append(current_range)
            current_range = None
            
        elif last_affected and current_range is not None:
            current_range["last_affected"] = last_affected
            res =  mapping_closest_ranges(sorted_versions,last_affected,False,True)
            
            value = None
            if (name,res) in versions_id_map:
                value = versions_id_map[(name,res)][1]
            
            current_range["last_affected_order_number"] = value
            grouped_ranges.append(current_range)
            current_range = None 
            
    if current_range is not None:
       grouped_ranges.append(current_range)
    return grouped_ranges

   
def find_versions_based_on_range(package_stored_versions,ranges_list):
    all_filtered_versions = list()
    for range in ranges_list:
        introduced = range["introduced"]
        fixed = range["fixed"]
        last_affected = range["last_affected"]
        filtered_versions = versions_filtering(package_stored_versions,introduced,fixed,last_affected)
        all_filtered_versions.extend(filtered_versions)
    return all_filtered_versions
  
  
##test this function    
def versions_filtering(package_stored_versions,introduced,fixed,last_affected):
    combined_specifier = None    
    if not introduced:
        return []
    
    introduced_specifier = None
    try:
        introduced_specifier = SpecifierSet(f">={introduced}")
    except InvalidSpecifier as e:
        print("invalied introduced specifier")
    combined_specifier = introduced_specifier
    if fixed:
        try:
            fixed_specifier = SpecifierSet(f"<{fixed}")
            combined_specifier = combined_specifier & fixed_specifier
        except InvalidSpecifier as e:
            print("invalied fixed specifier")
    
    if last_affected:
        try:
            last_affected_specifier = SpecifierSet(f"<={last_affected}")
            combined_specifier = combined_specifier & last_affected_specifier
        except InvalidSpecifier as e:
            print("invalid last affected specifier")
    
    if combined_specifier:
        return sorted(list(combined_specifier.filter(package_stored_versions)))
    return list()


def read_OSV_file(directory):
    conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                                    database='vulnerability_tracking')
    dir_path = Path(directory)
    
    vulnerability_batch_list = list()
    ranges_batch = list()
    versions_batch = list()
    cve_batch = list()
    BATCH_SIZE = 500
    
    packages_versions_map,versions_id_map = get_all_package_versions(conn)
    for file in dir_path.iterdir():
        if file.is_file():
            with open(file,"r") as OSV:
                vulnerability = json.load(OSV)
                if len(vulnerability_batch_list) >= BATCH_SIZE:
                    insert_vulnerabilities(vulnerability_batch_list,conn)
                    vulnerability_batch_list.clear()
                if len(ranges_batch) >= BATCH_SIZE:
                    insert_vulnerability_range(ranges_batch,conn)
                    ranges_batch.clear()
                if len(versions_batch) >= BATCH_SIZE:
                    insert_affected_packages(versions_batch,conn)
                    versions_batch.clear()
                if len(cve_batch) >= BATCH_SIZE:
                    insert_CVE(cve_batch,conn)
                    cve_batch.clear()
                process_vulnerability(vulnerability,conn,packages_versions_map,vulnerability_batch_list,ranges_batch,versions_batch,cve_batch,versions_id_map)
        print(f"Finished procesing: {file}")
    if vulnerability_batch_list:
        insert_vulnerabilities(vulnerability_batch_list,conn)
    if versions_batch:
        insert_affected_packages(versions_batch,conn)
    if ranges_batch:
        insert_vulnerability_range(ranges_batch,conn)
    if cve_batch:
        insert_CVE(cve_batch,conn)
    if conn:
        conn.close()

basepath = os.path.dirname(__file__)
DATA_DIRECTORY = "initial_data"
OSV_DATA = "all"
OSV_TEST_DATA = "test"
ALL_OSV_DATA_TEST = os.path.abspath(os.path.join(basepath, '../..', DATA_DIRECTORY,OSV_TEST_DATA))
ALL_OSV_DATA = os.path.abspath(os.path.join(basepath, '../..', DATA_DIRECTORY,OSV_DATA))


read_OSV_file(ALL_OSV_DATA)