package research.kg.gdb.database.repository;

import java.math.BigInteger;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import research.kg.gdb.database.model.Package;
import research.kg.gdb.database.model.Version;

public class SQLRepository {
    
    //this takes a connection object
    private Connection conn;

    public SQLRepository(Connection conn){
        this.conn = conn;
    }

    public Connection getConnection(){
        return this.conn;
    }

    public List<Package> getAllpackages(){
        List<Package> list = null;
        try ( Statement stmt = conn.createStatement();){
       
        stmt.setFetchSize(1000);
        try(ResultSet rs = stmt.executeQuery("SELECT id,name, is_deprecated , upload_time FROM package_metadata_v2");){
            list = new ArrayList<>();
            while( rs.next()){
                int id = rs.getInt("id");
                String name = (String) rs.getString("name");
                Boolean isDeprecated = (Boolean) rs.getBoolean("is_deprecated");
                Timestamp ut = rs.getTimestamp("upload_time");
                Package p = new Package(id,name,isDeprecated,ut);
                list.add(p);
            }
        }
        
        
        } catch (Exception e) {
            System.out.println(e);
        }
       
        return list;
    }


    public List<Map<String, Object>>  getAllVersions(){

        List<Map<String, Object>> version_maps = new ArrayList<>();
     
        try (Statement stmt = conn.createStatement();){

            stmt.setFetchSize(100);
            
            try (ResultSet rs = stmt.executeQuery("SELECT id,package_name_id,string_version,sequence_order from package_versions_v2");) {
                
            while(rs.next()){
                Map<String, Object> map = Map.of(
                "id", rs.getInt("id"),
                "package_name_id", rs.getInt("package_name_id"),
                "string_version",rs.getString("string_version"),
                "sequence_order",rs.getInt("sequence_order")
                );

			version_maps.add(map);
            }

            } catch (Exception e) {
               e.printStackTrace();
            }
            

        } catch (Exception e) {
           e.printStackTrace();
        }
        
        return version_maps;
        
    }


    public List<Map<String, Object>>  getPackageOnPackage(){

        List<Map<String, Object>> PackageOnPackageMap = new ArrayList<>();
     
        try (Statement stmt = conn.createStatement();){

            
            stmt.setFetchSize(100);
            try(ResultSet rs = stmt.executeQuery("SELECT distinct v.package_name_id as parent_package, d.dependency_package_name_id as dependency_package FROM dependencies_v2 d JOIN package_versions_v2 v ON d.parent_version_id = v.id;");)
            {

                while(rs.next()){
                    Map<String, Object> map = Map.of(
                    "parent", rs.getInt("parent_package"),
                    "dependency", rs.getInt("dependency_package")
                    );
                    PackageOnPackageMap.add(map);

                }

            }
  
        } catch (Exception e) {
           e.printStackTrace();
        }
        
        return PackageOnPackageMap;
        
    }


    public List<Map<String, Object>>  getVersionRequiresPackage(){

        List<Map<String, Object>> PackageOnPackageMap = new ArrayList<>();
     
        try (Statement stmt = conn.createStatement();){
            stmt.setFetchSize(100);

            try(ResultSet rs = stmt.executeQuery("SELECT * FROM dependencies_v2 d");)
            {
                
                while(rs.next()){

                    Map<String, Object> map = new HashMap<>();
                    map.put("parent", rs.getInt("parent_version_id"));
                    map.put("dependency_package_name_id",rs.getInt("dependency_package_name_id"));
                    map.put("constraint",rs.getString("specifier_string"));
                    map.put("lower_bound",rs.getInt("lower_bound_order_number"));
                    map.put("upper_bound",rs.getInt("upper_bound_order_number"));
			        PackageOnPackageMap.add(map);

                }

            }

        } catch (Exception e) {
           e.printStackTrace();
        }
        
        return PackageOnPackageMap;
        
    }

    public List<Map<String, Object>>  getVulnerabilities(){

        List<Map<String, Object>> vulnerabilities = new ArrayList<>();
     
        try {

            Statement stmt = conn.createStatement();
            stmt.setFetchSize(Integer.MIN_VALUE);
            ResultSet rs = stmt.executeQuery
            ("SELECT * FROM vulnerability_v2");
            
            while(rs.next()){
                Map<String, Object> map = new HashMap<>();
                map.put("id", rs.getString("id"));
                
                String summary = "";
                if (rs.getString("summary") == null){
                    summary = "no summary";
                }else{
                    summary = rs.getString("summary");
                }
                map.put("summary",summary);
			    
                vulnerabilities.add(map);
            }

        } catch (Exception e) {
           e.printStackTrace();
        }
        
        return vulnerabilities;
        
    }

    public List<Map<String, Object>> getVulnerabilitesOnPackage(){

        List<Map<String, Object>> vulnOnPackage = new ArrayList<>();

        try {

            Statement stm = conn.createStatement();
            stm.setFetchSize(100);
            ResultSet rs = stm.executeQuery("SELECT distinct vulnerability_id, package_id from vulnerability_range_v2");

            while(rs.next()){
                HashMap<String,Object> map = new HashMap<>();
                map.put("vuln_id",rs.getString("vulnerability_id"));
                map.put("package",rs.getInt("package_id"));
                vulnOnPackage.add(map);
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return vulnOnPackage;
    }

    public List<Map<String,Object>> getVulnerabilityIntroduced(){

        List<Map<String, Object>> introduced = new ArrayList<>();

        try (Statement stm = conn.createStatement();){

            
            stm.setFetchSize(1000);
            
            try(ResultSet rs = stm.executeQuery(
            "select r.vulnerability_id as vuln_id,v.id as version_id from vulnerability_range_v2 r\n" +
            "JOIN package_versions_v2 v ON v.package_name_id = package_id\n" +
            "AND v.sequence_order = r.introduced_version_order_number");){

                while(rs.next()){
                HashMap<String,Object> map = new HashMap<>();
                map.put("vuln_id",rs.getString("vuln_id"));
                map.put("version_id",rs.getInt("version_id"));
                introduced.add(map);
            }
            }
            
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return introduced;

    }

    public List<Map<String,Object>> getVulnerabilityFixed(){

        List<Map<String, Object>> fixed = new ArrayList<>();

        try (Statement stm = conn.createStatement();){

            
            stm.setFetchSize(1000);
            try(ResultSet rs = stm.executeQuery(
            "select r.vulnerability_id as vuln_id,v.id as version_id from vulnerability_range_v2 r\n" +
            "JOIN package_versions_v2 v ON v.package_name_id = package_id\n" +
            "AND v.sequence_order = r.fixed_version_order_number;");)
            {

                while(rs.next()){
                    HashMap<String,Object> map = new HashMap<>();
                    map.put("vuln_id",rs.getString("vuln_id"));
                    map.put("version_id",rs.getInt("version_id"));
                    fixed.add(map);
                }
            }
            

            
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return fixed;
    }

    public List<Map<String,Object>> getVulnerabilityLastAffected(){

        List<Map<String, Object>> lastAffected = new ArrayList<>();

        try (Statement stm = conn.createStatement();){

            
            stm.setFetchSize(100);

            try(ResultSet rs = stm.executeQuery(
            "select r.vulnerability_id as vuln_id,v.id as version_id from vulnerability_range_v2 r\n" +
            "JOIN package_versions_v2 v ON v.package_name_id = package_id\n" +
            "AND v.sequence_order = r.last_affected_version_order_number;");)
            
            {

                while(rs.next()){
                    HashMap<String,Object> map = new HashMap<>();
                    map.put("vuln_id",rs.getString("vuln_id"));
                    map.put("version_id",rs.getInt("version_id"));
                    lastAffected.add(map);
            }

            }
            

            
            
        } catch (Exception e) {
            e.printStackTrace();
        }

        return lastAffected;
    }
}
