
import re

import mysql.connector
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
import hashlib



def normalize(name):
    return re.sub(r"[-_.]+", "-", name).lower()

def get_all_package_versions(conn):
    local_cursor = conn.cursor(buffered=True)
    query_fetch = f"""
        select v.id, p.name, v.string_version as version from package_versions v
        JOIN package_metadata p ON p.id = v.package_id
    """
    local_cursor.execute(query_fetch)
    query_result = local_cursor.fetchall()
    
    packages_versions_map = dict()
    for row in query_result:
        name,version = row
        if name not in packages_versions_map:
            packages_versions_map[name] = []
        packages_versions_map[name].append(version)
    local_cursor.close()
    return packages_versions_map

insert_dependency = """
    INSERT INTO dependencies(parent_version_id, child_version_id)
    SELECT %(parent_version_id)s, v.id
    FROM package_versions_v2 v
    JOIN package_metadata_v2 p ON p.id = v.package_id
    WHERE p.name = %(name)s AND v.string_version = %(version)s
    ON DUPLICATE KEY UPDATE dependencies.id=dependencies.id;
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
fetch_database(batch_size=5000)


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