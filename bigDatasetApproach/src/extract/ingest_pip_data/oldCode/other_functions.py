def get_version_ids(req_dict,conn):
    ##similar as before, query the (name,v) present in the req_dict
    batch_versions = list(req_dict.keys())
    
    cursor = conn.cursor(buffered=True)
    placeholders = ", ".join(["(%s, %s)"] * len(batch_versions))
    version_lookup_query = f"""
    SELECT 
        p.name,
        v.string_version,
        v.id AS version_id
    FROM package_versions v
    JOIN package_metadata p ON p.id = v.package_id
    WHERE (p.name, v.string_version) IN ({placeholders});
    """
    flat_args = [item for pair in batch_versions for item in pair] 
         
    cursor.execute(version_lookup_query, flat_args)
    results = cursor.fetchall()
    dict_ids = dict()
    
    for name,version,version_id in results:
        dict_ids[(name,version)] =  version_id 
    cursor.close()
    return dict_ids

def insert_requirements(req_dict,version_ids,req_list):
    for (name,version) in req_dict:
        req = req_dict[(name,version)] 
        pack_id = version_ids[(name,version)]
        for r in req:
            req_list.append(
                {
                    "package_version_id" : pack_id,
                    "req": r
                }
            )
    return req_list  

def flatten_tuples(tuple_list):
    new_list = list()
    for i in tuple_list:
        new_list.append(i[0])
    return new_list

def get_ids(versions_dict,conn):
    package_names = list()
    for name in versions_dict.keys():
        package_names.append(name)
    
    if len(package_names) <=0:
        return {}
    cursor = conn.cursor(buffered=True)
    placeholders = ', '.join(['%s'] * len(package_names))
    
    query = f""" SELECT id,name from package_metadata_v2
    WHERE name IN ({placeholders})
    """        
    cursor.execute(query, package_names)
    results = cursor.fetchall()
    dict_ids = dict()
    for row in results:
        id,name = row
        if name not in dict_ids:
            dict_ids[name] = id
    return dict_ids


def insert_versions(ids,versions_map,versions):
    for name in versions_map:   
        versions_list = versions_map[name]
        package_id = ids[name]
        for v in versions_list:
            version = handle_versions(v)
            if len(version) <=0:
                print(version)
                continue
            versions.append({
                    "package_id" : package_id,
                    "version": version[0],
                    "major":version[1],
                    "minor":version[2],
                    "micro":version[3]
                    })
    return versions


##dependencies
for (id,req) in package_reqs:    
        package_name = package_reqs[(id,req)]
        list_1 = packages_versions.get(package_name)
        versions_list = list()
        id_map = dict()
        for i in list_1:
            versions_list.append(i[0])
            if (package_name,i[0]) not in id_map:
                id_map[(package_name,i[0])] = []
            id_map[(package_name,i[0])].append(i[1])
        
        if not versions_list:
            continue
        specifier = req.specifier
        required_dep = list(specifier.filter(versions_list))
        for i in required_dep:
            child_id = id_map[((package_name,i))]
            # req_all_packages.append((id,child_id))