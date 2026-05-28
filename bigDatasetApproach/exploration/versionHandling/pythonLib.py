from packaging.version import Version, parse
from packaging.specifiers import SpecifierSet
from packaging.requirements import Requirement
import json

#Use packaging library to handle version specifiers
v0 = Version("1.0")
v1 = Version("0.0.1.dev1")
v2 = Version("0.0.1.dev2")
v3 = Version("0.0.1.dev3")
v4 = Version("1.1.5")

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
"""
"dependencies": ["redis (>=2.10.5)"]
"""

with open("test_dependency.json","r") as file:
    data = json.load(file)
    i = data[1]
    name = i.get("name")
    version = i.get("version")
    dependencies = i.get("dependencies")
    dict_requirement = handleDependencies(dependencies)
    print(dict_requirement)
    example_version = Version("2.0")
    if example_version in dict_requirement.get("specifier"):
        print("version corresponds")
    else:
        print("inadaquate version")

req = Requirement('mcp[cli]\u003e\u003d1.9.4')
print(req)
print( {
            "name": req.name,
            "url": req.url,
            "extras": req.extras,
            "specifier": req.specifier,
            "marker": req.marker
} )

