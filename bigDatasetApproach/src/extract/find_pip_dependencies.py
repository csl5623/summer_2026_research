
import mysql.connector
from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement


conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)

##instead of recursion use iterative BFS/DFS 
def find_dependencies(name,r,):
        dep = requirements[(name,r)]
        req_dict = dict()
        for d in dep:
            req = Requirement(d)            
            n = req.name
            specifier = req.specifier
            extra = req.extras
            
            ##this will need to be a sql query            
            package_versions = versions.get(n, set())
            required_dep = list(specifier.filter(list(package_versions)))
            print("FILTEREDDDD DEPENDENCIEEEESSSS---------")
            print(required_dep)
            
            if n not in req_dict:
                req_dict[n] = []
                
            req_dict[n].append(required_dep)
            for required in required_dep:
                    if (n,required) in visited:
                        continue
                    visited.add((n,required))
                    find_dependencies(n,required)
                  
        if (name,r) not in package_dependencies:
            package_dependencies[(name,r)] = []
        package_dependencies[(name,r)] = req_dict
        


def fetch_database():
    
    query_fetch = "SELECT version_id,requirement FROM package_versions"
    cursor.execute(query_fetch)
    while True:
        batch = cursor.fetchmany(size=5000)
        if not batch:
            break

        explore_entire_graph(batch)
    


def explore_entire_graph(graph):
    visited = set()
    all_traversals = []

    # The outer loop ensures NO node is left behind
    for version_id,requirement in graph:
        
        if version_id in visited:
            continue
            
        # Otherwise, we found a new component. Start an iterative DFS here.
        component_path = []
        stack = [version_id]
        
        while stack:
            current = stack.pop()
            
            if current not in visited:
                visited.add(current)

                req = Requirement(requirement)            
                n = req.name
                specifier = req.specifier
                extra = req.extras
                
                
                get_packages_for_req = """
                SELECT version_id,string_version FROM package_version joined with requirements table
                """

                ##get all string versions
                package_versions = query_result[1]
                version_dependencies = list(specifier.filter(list(package_versions)))                
                # Push unvisited neighbors
                for version in version_dependencies:
                    if version not in visited:
                        stack.append(version)
        
        all_traversals.append(component_path)

    return all_traversals