package research.kg.gdb.database.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Map;


import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;


import research.kg.gdb.database.repository.SQLRepository;
import research.kg.gdb.database.repository.Neo4jConfig;


import java.util.ArrayList;
import java.util.List;


import research.kg.gdb.database.model.Package;

public class VulnGraphDB {

	public static void oldCode(SQLRepository sqlrepo ,Neo4jConfig neo4jConfig){
		GraphDatabaseService db = neo4jConfig.getGraphDB();

		//queries for getting packages
		List<Package> p = sqlrepo.getAllpackages();
		//queries for creating nodes

		var createPackageNodes = 
            "UNWIND $packages AS row\n" + 
            "CREATE (p:Package {id: row.id ,name: row.name })"
        ;
        
		List<Map<String, Object>> package_nodes = new ArrayList<>();
		for (Package pck: p){
			Map<String, Object> map = Map.of(
			"id", pck.getId(),
			"name", (String) pck.getName()
			);
			package_nodes.add(map);
		}
		
		try (Transaction tx = db.beginTx()){
			Result result2 = tx.execute(createPackageNodes,Map.of("packages",package_nodes));
			System.out.println(result2.resultAsString());
			tx.commit();
		} catch (Exception e) {
			e.printStackTrace();
		}
		String versions_query = """
        UNWIND $versions AS row 
		MATCH (p: Package {id: row.package_name_id}) 
		CREATE (p)-[:HAS]->(v:Version {id:row.id, string_version:row.string_version, order_number:row.sequence_order})    
        """;

		List<Map<String, Object>> versionsMap = sqlrepo.getAllVersions();
		int batchSize = 100;
		
		//send data to neo4j in batches?? to fix outofmemory error
		for (int i = 0; i < versionsMap.size(); i += batchSize) {
            int end = Math.min(versionsMap.size(), i + batchSize);
            
            List<Map<String, Object>> batch = versionsMap.subList(i, end);
            
			try (Transaction tx = db.beginTx()){
				Result result2 = tx.execute(versions_query,Map.of("versions",batch));
				System.out.println(result2.resultAsString());
				tx.commit();

			} catch (Exception e) {
				e.printStackTrace();
			}

			 System.out.println("done with batch");
           
        }

		neo4jConfig.shutdown();
	}

	public static void main(String[] args) {
		final String neo4jFolder = "DB_FOLDER", database = "database";
		
		String stringURL = "jdbc:mysql://localhost:3306/vulnerability_tracking?useCursorFetch=true";
		String username = "root"; 
		String password = "carlitaxbarca";
		Connection conn = null;
		try {
			 conn = DriverManager.getConnection(stringURL, username, password);
		} catch (Exception e) {
			
		}
		SQLRepository sqlrepo = new SQLRepository(conn);
		Neo4jConfig neo4jConfig = new Neo4jConfig(neo4jFolder, database);
		
		MigrateNeo4j migrate = new MigrateNeo4j(sqlrepo, neo4jConfig);

		// System.out.println("Creating indexes");
		// migrate.createIndexes();
		// System.out.println("Creating pacakge");
		// migrate.createPackageNodes();
		// migrate.createVersionNodes();
		// System.out.println("Creating package on pacakge relationship");
		// migrate.PackageOnPackageRelationship();
		// // System.out.println("creating version on package");
		// // migrate.versionOnPackageRelationship();
		// System.out.println("vulnerabilities");
		// migrate.createVulnNodes();
		// migrate.vulnOnPackageRel();
		// System.out.println("creating vuln relationships");
		// migrate.vulnIntroducedRel();
		// migrate.vulnLastAffected();
		// migrate.vulnFixedRel();
		// migrate.exportDatabase("vulnDB");
		migrate.shutDownNeo4j();
		
	}

}

