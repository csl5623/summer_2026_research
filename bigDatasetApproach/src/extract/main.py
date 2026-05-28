

import glob
import os

import json
import mysql.connector
from zipfile import ZipFile
from itertools import count
import pandas as pd
from itertools import batched


conn = mysql.connector.connect(user='root', password='carlitaxbarca',
                              database='vulnerability_tracking', allow_local_infile=True)
cursor = conn.cursor(buffered=True)
basepath = os.path.dirname(__file__)

DATA_DIRECTORY = "initial_data"
PYPI_DATA_ZIP = "pypi_metadata.zip"
PYPI_DATA_PATH = os.path.abspath(os.path.join(basepath, '..', DATA_DIRECTORY,PYPI_DATA_ZIP))
CSV_DIRECTORY_PATH = os.path.abspath(os.path.join(basepath, "csv"))
BATCH_SIZE = 5000


def load_pypi_initial_data(zip,jsonFile,iterator):
    package_query = """
                INSERT INTO package_metadata(id,name,version)
                VALUES (%s,%s,%s)
                
                """
    requirements_query = """
                INSERT INTO package_requirements(package_id,requirement)
                VALUES (%s,%s)
                """
    package_list = []
    requirements_data = []
    with zip.open(jsonFile,'r') as file:
        for line in file:
                json_clean = line.strip()
                data = json.loads(json_clean)
                
                name = data.get("name")
                version = data.get("version")
                dependencies = data.get("dependencies")
                row_id = next(iterator)
                
                package_data = (row_id,name,version)
                package_list.append(package_data)
                
                for d in dependencies:
                    dependencies_data = (row_id,d)
                    requirements_data.append(dependencies_data)
                    
                if len(package_list) >= BATCH_SIZE:
                    cursor.executemany(package_query, package_list)
                    conn.commit()
                    package_list = []
                           
        if package_list:
            cursor.executemany(package_query, package_list)            
        conn.commit()
    
    for batch in batched(requirements_data, BATCH_SIZE):
        cursor.executemany(requirements_query, batch)
        conn.commit()
        
    print(f"finished processing a file: {jsonFile}")

##Open Zipfile and load data into batches
def openZipFile(path):
    with ZipFile(path,"r") as zip:
        jsonFiles = zip.namelist()
        counter = count(1)
        for i in jsonFiles:
            if i.startswith("__MACOSX"):
                continue
            if i.endswith(".json"):
                load_pypi_initial_data(zip,i,counter)
                
openZipFile(PYPI_DATA_PATH)
    
def convert_json_into_csv(zip,json_file,iterator):
    with zip.open(json_file,'r') as file:
        allRows = []
        requirements = []
        file_id = None
        for line in file:
            json_clean = line.strip()
            data = json.loads(json_clean)
            
            name = data.get("name")
            version = data.get("version")
            dependencies = data.get("dependencies")
            row_id = next(iterator)
            
            if file_id is None:
                file_id = row_id
                
            package_data = {"row_id":row_id,"name":name,"version":version}
            allRows.append(package_data)
            for i in dependencies:
                dependencies_data = {"package_id":row_id,"requirement":i}
                requirements.append(dependencies_data)
        
        if allRows:
            df = pd.DataFrame(allRows)
            df.to_csv(f'{CSV_DIRECTORY_PATH}/package_metadata/{file_id}.csv', index=False)
        if requirements:
            df = pd.DataFrame(requirements)
            df.to_csv(f'{CSV_DIRECTORY_PATH}/requirements/{file_id}.csv', index=False)




