
import json 
import os
import requests

ECOSYSTEM = 'PyPI'
URL = "https://api.osv.dev/v1/query"
def load_data():
    with open('pypidatabase.json','r') as database:
        data = json.load(database)
        for i in data:
            name = i.get("name")
            version = i.get("version")
            find_vulnerabilities(name,version)
            
            
def find_vulnerabilities(name,version):
    print(version)
    parameters = { "package": { "name": name, "ecosystem": ECOSYSTEM}}
    response = requests.post(URL,json=parameters)
    if response.request == 400:
        print("VULNERABILITY NOT FOUND")
        return 
    else:
        data = response.json()
        if not data:
            print("NOT FOUND VULNERABILITY")
            return
        vulnerability = data['vulns']
        print(name)
        # with open(f"vulnerability_{name}.json","w") as file:
        #     json.dump(vulnerability,file,indent=4)
        for v in vulnerability:
            affected = v.get("affected")
            
            for i in affected:        
                ##find affected versions
                API_versions_array = set(affected["versions"])
                print(API_versions_array)

# load_data()
# find_vulnerabilities("requests",1)

import uuid

uuid_v5 = uuid.uuid5(uuid.NAMESPACE_DNS, "request|1.3.4")
print(uuid_v5.bytes)
