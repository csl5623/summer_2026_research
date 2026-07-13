from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
import json
import mysql.connector

#Use packaging library to handle version specifiers
v0 = Version("1.2.0")
v1 = Version("0.0.1.dev1")
v2 = Version("0.0.1.dev2")
v3 = Version("0.0.1.dev3")
v4 = Version("1.1.5")

print(v0.micro)

print("SORTING VERSIONS")
print(sorted([v0,v1,v2,v3,v4]))


print("FINDING IF DEPENDENCY BELONGS OR NOT TO Dependency requirement")
def handleDependencies(dependencies):
    depDict = dict()
    for i in range(len(dependencies)):
        req = Requirement(dependencies[i])
        depDict[i] = {
            "name": req.name,
            "url": req.url,
            "extras": req.extras,
            "specifier": req.specifier,
            "marker": req.marker
    }
    return depDict[i]

##small demo using data from Pypi Big Query Dataset and Packaging library   
# """
# "dependencies": ["redis (>=2.10.5)"]
# """

# with open("test_dependency.json","r") as file:
#     data = json.load(file)
#     i = data[1]
#     name = i.get("name")
#     version = i.get("version")
#     dependencies = i.get("dependencies")
#     dict_requirement = handleDependencies(dependencies)
#     print(dict_requirement)
#     example_version = Version("2.0")
#     if example_version in dict_requirement.get("specifier"):
#         print("version corresponds")
#     else:
#         print("inadaquate version")

conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)

def get_all_package_versions(conn):
    name = "requests"
    local_cursor = conn.cursor(buffered=True)
    query_fetch = f"""
        select p.name, v.string_version as version from package_versions v
        JOIN package_metadata p ON p.id = v.package_id
        WHERE name = (%s)
        """
    local_cursor.execute(query_fetch,(name,))
    query_result = local_cursor.fetchall()
    
    list_1 = []
    print("fetching rows")
    for row in query_result:
        version = row[1]
        list_1.append(version)
    local_cursor.close()
    print("finished fetching rows")
    return list_1

# versions_2 = get_all_package_versions(conn)
# print(sorted(versions_2,key=parse))
req = Requirement('requests != 2.8.1, == 2.8.* ; python_version < "3.7"')
specifier = req.specifier._get_ranges()
for i in specifier:
    print(i)

valid_versions = []
not_versions = [] 



req = Requirement("requests ~= 2.8.1")
specifier = list(req.specifier)[0] # Grab the ~= 2.8.1 specifier


p = "2026.1.12.*"



spec = SpecifierSet("==2026.1.12.*")
print(spec._get_ranges()[0])

v = Version("1.0.4")
v2 = Version(None)



v = max(v,None)  
print(v) 