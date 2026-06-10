
import mysql.connector
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
import hashlib


##instead of recursion use iterative BFS/DFS 
insert_dependency = """
INSERT INTO dependencies(parent_version_id,dependency_package_version_id)
VALUES (%s,%s)
"""
def generate_id(string):
    hash_bytes = hashlib.sha256(string.encode('utf-8')).hexdigest()
    return hash_bytes

def store_dependencies(result,conn):
    package_reqs = dict()
    for row in result:
        id, requirement = row
        if requirement:
            req = Requirement(requirement)  
            req_name = req.name
            if id not in package_reqs:
                package_reqs[(id,req)] = req_name
    
    local_cursor = conn.cursor(buffered=True)
    req_all_packages = list()
    for (id,req) in package_reqs:    
        package_name = package_reqs[(id,req)]
        print(package_name)
        query_fetch = f"""
        select v.string_version as version from vulnerability_tracking.package_versions v
        JOIN vulnerability_tracking.package_metadata p ON p.id = v.package_id
        WHERE p.name  = (%s)
        """
        local_cursor.execute(query_fetch,(package_name,))
        package_versions = local_cursor.fetchall()
        item_list = [row[0] for row in package_versions]
        specifier = req.specifier
        required_dep = list(specifier.filter(item_list))
        for i in required_dep:
                req_all_packages.append((id,generate_id(f'{package_name}|{i}')))
    
    local_cursor.close()
    insert_cursor = conn.cursor(buffered=True)
    insert_cursor.executemany(insert_dependency,(req_all_packages))
    conn.commit()
    insert_cursor.close()
    
    
def fetch_database(batch_size):
        try:
            conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                                    database='vulnerability_tracking')
            cur = conn.cursor(buffered=True)
            query_fetch = f"""
                select v.id, r.requirement from vulnerability_tracking.package_versions v
                JOIN vulnerability_tracking.package_metadata p ON p.id = v.package_id
                JOIN vulnerability_tracking.package_requirements r ON r.package_version_id = v.id;
                """
            cur.execute(query_fetch)    
            while True:
                    rows = cur.fetchmany(size=batch_size)
                    if not rows:
                        break
                    print(f"Processing {len(rows)}")
                    store_dependencies(rows,conn)

        except Exception as e:
            print("errror")
            print(e)
        if cur:
            cur.close()
        if conn:
            conn.close()

fetch_database(batch_size=5000)

