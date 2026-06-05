

import feedparser
import re
import requests
import mysql.connector
import json


##Logic for new packages
SIMPLE_API_END_POINT = "https://pypi.org/simple/"
headers = {
    "Accept": "application/vnd.pypi.simple.v1+json"
}
response = requests.get(SIMPLE_API_END_POINT, headers=headers)
api_json = response.json()

SIMPLE_API_SET = set()
for i in api_json["projects"]:
    SIMPLE_API_SET.add(i["name"])

conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)


##add is deleted column to table
query = """
select DISTINCT name from vulnerability_tracking.package_metadata;
"""
cursor.execute(query)
data = cursor.fetchall()

DATABASE_SET = set()
for value in data:
    DATABASE_SET.add(value[0])

DELETED_PACKAGES = DATABASE_SET - SIMPLE_API_SET
print(len(DELETED_PACKAGES))

MISSING_PACKAGES = SIMPLE_API_SET - DATABASE_SET
print(len(MISSING_PACKAGES))


# ##call the JSON API for all this packages
# for package in MISSING_PACKAGES:
#     JSON_API_END_POINT = 'https://pypi.org/pypi/'+ package + '/json'
#     response = requests.get(JSON_API_END_POINT)
#     json_object = response.json()
#     with open(f"data{package}.json","w") as file:
#         json.dump(json_object,file,indent=4)
    
##process their dependencies
##get vulnerabilities
##put them in database