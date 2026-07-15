package research.kg.gdb.database.service;

import java.sql.Connection;
import java.sql.DriverManager;
import java.util.Map;


import org.neo4j.graphdb.GraphDatabaseService;
import org.neo4j.graphdb.Result;
import org.neo4j.graphdb.Transaction;


import research.kg.gdb.database.repository.SQLRepository;
import research.kg.gdb.database.repository.Neo4jConfig;

import org.neo4j.graphdb.Transaction;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import org.neo4j.graphdb.GraphDatabaseService;



import research.kg.gdb.database.model.Package;

public class VulnGraphDB {

	public static void migrateInfo(SQLRepository sqlrepo,Neo4jConfig neo4jConfig){
		MigrateNeo4j migrate = new MigrateNeo4j(sqlrepo, neo4jConfig);
		System.out.println("Creating indexes");
		migrate.createIndexes();
		System.out.println("Creating pacakge");
		migrate.createPackageNodes();
		migrate.createVersionNodes();
		System.out.println("Creating package on pacakge relationship");
		migrate.PackageOnPackageRelationship();
		System.out.println("creating version on package");
		migrate.versionOnPackageRelationship();
		System.out.println("vulnerabilities");
		migrate.createVulnNodes();
		migrate.vulnOnPackageRel();
		System.out.println("creating vuln relationships");
		migrate.vulnIntroducedRel();
		migrate.vulnLastAffected();
		migrate.vulnFixedRel();
		migrate.vulnerabilityAffectPackageVersion();
		migrate.shutDownNeo4j();
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
		// MigrateNeo4j migrate = new MigrateNeo4j(sqlrepo, neo4jConfig);
		// migrate.vulnerabilityAffectPackageVersion();
		
		Map<String, Object> parameters = new HashMap<>();
		// envdrift
		// pydantic
        parameters.put("package","envdrift");
        parameters.put("version","10.8.0");
        
		String query = """

		MATCH (p:Package {name: $package})-[:HAS]->(v:Version {string_version: $version})
		
		MATCH path = (v) (
			(src)-[r:REQUIRES]->(d:Package)-[:HAS]->(dep:Version)
			WHERE r.version_lower_bound <= dep.order_number <= r.version_upper_bound
		){1}

		UNWIND dep as individualDep
		MATCH (vuln:Vulnerability)-[:AFFECTS_VERSION]->(individualDep)
		MATCH (depPackage:Package)-[:HAS]->(individualDep)

		return depPackage.name, vuln.id, individualDep.string_version
		""";

		String query2 = """

		

		MATCH (vuln:Vulnerability)-[:AFFECTS]->(p:Package {name: $package})
		return vuln.id
		""";

	// lsof /Users/carlalopez/dev/summer_research/summer_2026_research/neo4j/DB_FOLDER/database/data/databases/store_lock
    	try (Transaction tx = neo4jConfig.getGraphDB().beginTx()){
			Result rs = tx.execute(query,parameters);
			System.out.println(rs.resultAsString());
            tx.commit();
		}
		neo4jConfig.shutdown();
	}

}

