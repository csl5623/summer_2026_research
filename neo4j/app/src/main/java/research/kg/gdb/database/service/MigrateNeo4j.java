package research.kg.gdb.database.service;

import research.kg.gdb.database.repository.*;


import java.sql.Connection;
import java.sql.ResultSet;
import java.util.Map;

import org.neo4j.common.DependencyResolver;
import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;
import org.neo4j.internal.kernel.api.exceptions.ProcedureException;
import org.neo4j.kernel.api.procedure.GlobalProcedures;
import org.neo4j.kernel.internal.GraphDatabaseAPI;

import apoc.ApocConfig;
import apoc.export.graphml.ExportGraphML;

import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import apoc.ApocConfig;
import apoc.export.graphml.ExportGraphML;


import research.kg.gdb.database.model.Package;


public class MigrateNeo4j {
    
    private SQLRepository sqlrepo;
	private Neo4jConfig neo4jConfig;
    private GraphDatabaseService db;

    public MigrateNeo4j(SQLRepository sqlrepo, Neo4jConfig neo4jConfig){
        this.sqlrepo = sqlrepo;
        this.neo4jConfig = neo4jConfig;
        this.db = this.neo4jConfig.getGraphDB();
    }

    public void createIndexes(){
        try (Transaction tx = db.beginTx()) {

            tx.execute("CREATE CONSTRAINT package_id_idx IF NOT EXISTS FOR (p:Package) REQUIRE p.id IS UNIQUE");
            
            tx.execute("CREATE CONSTRAINT version_id_idx IF NOT EXISTS FOR (v:Version) REQUIRE v.id IS UNIQUE");
            
            tx.execute("CREATE CONSTRAINT vuln_id_idx IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE");
            
            tx.commit();
            System.out.println("All database indexes and constraints successfully verified.");
        } catch (Exception e) {
            System.err.println("Error initializing indexes:");
            e.printStackTrace();
        }
    }

    private void createNodesInBatches(String query, int batchSize, List<Map<String, Object>> map){

        for (int i = 0; i < map.size(); i += batchSize) {
            int end = Math.min(map.size(), i + batchSize);
            
            List<Map<String, Object>> batch = map.subList(i, end);
            
			try (Transaction tx = db.beginTx()){
				Result result2 = tx.execute(query,Map.of("map",batch));
				System.out.println(result2.resultAsString());
                tx.commit();
			} catch (Exception e) {
				e.printStackTrace();
			}
			System.out.println("done with batch");
        }
        

    }
    
    public void createPackageNodes(){
        List<Package> p = sqlrepo.getAllpackages();
        var createPackageNodes = 
            "UNWIND $map AS row\n" + 
            "MERGE (p:Package {id: row.id})\n" +
            "SET p.name = row.name";
        
		List<Map<String, Object>> package_nodes = new ArrayList<>();
		for (Package pck: p){
			Map<String, Object> map = Map.of(
			"id", pck.getId(),
			"name", (String) pck.getName()
			);
			package_nodes.add(map);
		}

		createNodesInBatches(createPackageNodes, 1000, package_nodes);
    }

    public void createVersionNodes(){
        String versions_query = """
        UNWIND $map AS row 
		MATCH (p: Package {id: row.package_name_id}) 
		MERGE (v:Version {id:row.id}) 
        ON CREATE SET v.string_version = row.string_version, v.order_number = row.sequence_order   
        MERGE (p)-[:HAS]->(v)
        """;

		List<Map<String, Object>> versionsMap = sqlrepo.getAllVersions();
		int batchSize = 1000;
		
		//send data to neo4j in batches?? to fix outofmemory error
        createNodesInBatches(versions_query, batchSize, versionsMap);
    }

    public void PackageOnPackageRelationship(){
        List<Map<String, Object>> packageOnPackageList = sqlrepo.getPackageOnPackage();

        String versions_query = """
        UNWIND $map AS row 
		MATCH (p: Package {id: row.parent})
        MATCH (d: Package {id: row.dependency})  
		MERGE (p)-[:DEPENDS_ON]->(d)    
        """;

        int batchSize = 1000;

        createNodesInBatches(versions_query, batchSize, packageOnPackageList);
    }

    public void versionOnPackageRelationship(){

        Connection conn = sqlrepo.getConnection();

        List<Map<String, Object>> PackageOnPackageMap = new ArrayList<>();
        String versions_query = """
            UNWIND $map AS row 
            MATCH (v: Version {id: row.parent})
            MATCH (d: Package {id: row.dependency})  
            MERGE (v)-[r:REQUIRES {version_lower_bound: row.lower_bound , version_upper_bound: row.upper_bound}]->(d)
            ON CREATE SET r.constraint = row.constraint 
        """;

        int batchSize = 1000;
     
        try (Statement stmt = conn.createStatement();){
            stmt.setFetchSize(1000);

            try(ResultSet rs = stmt.executeQuery("SELECT * FROM dependencies_v2 d");)
            {
                
                while(rs.next()){

                    Map<String, Object> map = new HashMap<>();
                    map.put("parent", rs.getInt("parent_version_id"));
                    map.put("dependency",rs.getInt("dependency_package_name_id"));
                    map.put("constraint",rs.getString("specifier_string"));
                    
                    //lower bound eveluating to zero is fine (0 points to first stored value)
                    map.put("lower_bound",rs.getInt("lower_bound_order_number"));
                    
                    //if upper bound is null,means it is the ceiling (so infinity (in this case a huge int))
                    int upper_bound = Integer.MAX_VALUE;
                    if (rs.getObject("upper_bound_order_number") != null){
                        System.out.println();
                        upper_bound = rs.getInt("upper_bound_order_number");

                    }else{
                        System.out.println("null value found");
                    }

                    map.put("upper_bound",upper_bound);
			        PackageOnPackageMap.add(map);

                    if (PackageOnPackageMap.size() >= 100000){
                        createNodesInBatches(versions_query, batchSize, PackageOnPackageMap);
                        PackageOnPackageMap.clear();
                    }

                }

            }

        } catch (Exception e) {
           e.printStackTrace();
        }

        if (PackageOnPackageMap.size() > 0){
            int batch_size = PackageOnPackageMap.size();
            createNodesInBatches(versions_query, batch_size, PackageOnPackageMap);
            PackageOnPackageMap.clear();
        }  

    }

    public void createVulnNodes(){
        List<Map<String, Object>> vulns = sqlrepo.getVulnerabilities();

        String vulns_query = """
            UNWIND $map AS row 
            MERGE (v:Vulnerability {id:row.id, summary:row.summary})
        """;

        int batchSize = 1000;
        createNodesInBatches(vulns_query, batchSize, vulns);

    }

    public void vulnOnPackageRel(){
        List<Map<String,Object>> vulnOnPackage = sqlrepo.getVulnerabilitesOnPackage();

        String query = """
            UNWIND $map AS row
            MATCH (p:Package {id:row.package})
            MATCH (vuln:Vulnerability {id: row.vuln_id})
            MERGE (v)-[:AFFECTS]->(p)
            """;
        int batchSize = 1000;
        createNodesInBatches(query, batchSize, vulnOnPackage);
    }


    public void vulnIntroducedRel(){
        List<Map<String,Object>> vulnOnPackage = sqlrepo.getVulnerabilityIntroduced();

        String query = """
            UNWIND $map AS row
            MATCH (v:Version {id:row.version_id})
            MATCH (vuln:Vulnerability {id: row.vuln_id})
            MERGE (vuln)-[:INTRODUCED_IN]->(v)
            """;
        int batchSize = 1000;
        createNodesInBatches(query, batchSize, vulnOnPackage);
    }

    public void vulnFixedRel(){

        List<Map<String,Object>> vulnOnPackage = sqlrepo.getVulnerabilityIntroduced();

        String query = """
            UNWIND $map AS row
            MATCH (v:Version {id:row.version_id})
            MATCH (vuln:Vulnerability {id: row.vuln_id})
            MERGE (vuln)-[:FIXED_IN]->(v)
            """;
        int batchSize = 100;
        createNodesInBatches(query, batchSize, vulnOnPackage);

    }

    public void vulnLastAffected(){
        List<Map<String,Object>> vulnOnPackage = sqlrepo.getVulnerabilityIntroduced();
        String query = """
            UNWIND $map AS row
            MATCH (v:Version {id:row.version_id})
            MATCH (vuln:Vulnerability {id: row.vuln_id})
            MERGE (vuln)-[:LAST_AFFECTED]->(v)
            """;
        int batchSize = 100;
        
        createNodesInBatches(query, batchSize, vulnOnPackage);

    }

    public void exportDatabase(String fileName){
        DependencyResolver resolver = ((GraphDatabaseAPI) db).getDependencyResolver();
		GlobalProcedures procedures = resolver.resolveDependency( GlobalProcedures.class, DependencyResolver.SelectionStrategy.SINGLE);
			
		try {
            procedures.registerProcedure(ExportGraphML.class);
            ApocConfig.apocConfig().setProperty(ApocConfig.APOC_EXPORT_FILE_ENABLED, true);
            try(Transaction tx = db.beginTx()){
            Result res = tx.execute("CALL apoc.export.graphml.all(\""+fileName+"\", {readLabels: true, storeNodeIds: true, useTypes: true})");
            System.out.println(res.resultAsString());
        }
        } catch (ProcedureException e) {
            e.printStackTrace();
        }
    }


    public void shutDownNeo4j(){
        this.neo4jConfig.shutdown();
    }
}