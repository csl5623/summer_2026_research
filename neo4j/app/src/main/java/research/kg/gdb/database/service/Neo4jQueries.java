package research.kg.gdb.database.service;

import org.neo4j.graphdb.GraphDatabaseService;

import research.kg.gdb.database.repository.Neo4jConfig;
import research.kg.gdb.database.repository.SQLRepository;
import org.neo4j.graphdb.Transaction;
import org.neo4j.graphdb.Result;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.neo4j.graphdb.GraphDatabaseService;

public class Neo4jQueries {
    
    private Neo4jConfig neo4jConfig;
    private GraphDatabaseService db;

    public Neo4jQueries(Neo4jConfig neo4jConfig){
        this.neo4jConfig = neo4jConfig;
        this.db = this.neo4jConfig.getGraphDB();
    }
     

    public void getPackagesWithVulnerabilities(){
        String query = """
		MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)
		return count(p)
		""";
		try(Transaction tx = db.beginTx()){
			Result rs = tx.execute(query);
			System.out.println(rs.resultAsString());
            tx.commit();
		}
    }

    public void numberOfVulnerableVersions(){
                String query = """
			CYPHER 25 MATCH (v:Vulnerability)-[:AFFECTS]->(p:Package)
			MATCH (v)-[:INTRODUCED_IN]->(verInt:Version)
			
    		OPTIONAL MATCH (v) -[:LAST_AFFECTED]->(verLast:Version)
			OPTIONAL MATCH (v)-[:FIXED_IN]->(verFixed:Version)

			CALL (*) {
				WHEN verLast is NOT null THEN {
					MATCH (p)-[:HAS]->(ver:Version)
					WHERE ver.order_number >= verInt.order_number
					AND ver.order_number <= verLast.order_number
					return ver
				}
				WHEN verFixed is NOT null THEN {
					MATCH (p)-[:HAS]->(ver:Version)
					WHERE ver.order_number >= verInt.order_number
					AND ver.order_number < verFixed.order_number
					return ver
				}
				ELSE {
					MATCH (p)-[:HAS]->(ver:Version)
					WHERE ver.order_number >= verInt.order_number
					return ver
				}
			}
			RETURN count(distinct ver) as numberOfVulnerableNodes
    
            """;

        try(Transaction tx = neo4jConfig.getGraphDB().beginTx()){
                Result rs = tx.execute(query);
                System.out.println(rs.resultAsString());
                tx.commit();
        }

    }

    public void findingTransitiveDependencies(String pack,String version){
        Map<String, Object> parameters = new HashMap<>();
        parameters.put("package",pack);
        parameters.put("version",version);
        String query = """
			
            MATCH (p:Package {name: $package})-[:HAS]->(v:Version {string_version: $version})
			MATCH path = (v) ((:Version)-[r:REQUIRES]->(d:Package)-[:HAS]->(dep:Version)
			where dep.order_number >= r.version_lower_bound and dep.order_number <= r.version_upper_bound){2}

			UNWIND nodes(path) as n
			WITH n WHERE n:Version

			MATCH (depPack:Package)-[:HAS]->(n)
			WHERE depPack.name <> $package
			RETURN depPack.name, count(DISTINCT n)
			
        """;
    // lsof /Users/carlalopez/dev/summer_research/summer_2026_research/neo4j/DB_FOLDER/database/data/databases/store_lock
        try(Transaction tx = neo4jConfig.getGraphDB().beginTx()){
			Result rs = tx.execute(query,parameters);
			System.out.println(rs.resultAsString());
            tx.commit();
		}
    }

    public void shutDown(){
        this.neo4jConfig.shutdown();
    }


}
