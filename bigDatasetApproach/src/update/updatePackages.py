import mysql.connector
import requests

conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)


##fetch all ROWS from table
 
##Logic for new packages
SIMPLE_API_END_POINT = "https://pypi.org/pypi/pygetweb/json"
# headers = {
#     "Accept": "application/vnd.pypi.simple.v1+json"
# }
response = requests.get(SIMPLE_API_END_POINT)
api_json = response.json()
print(api_json)