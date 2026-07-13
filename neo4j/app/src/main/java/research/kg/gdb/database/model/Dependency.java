package research.kg.gdb.database.model;

import java.math.BigInteger;

public class Dependency {
    
    private BigInteger parent_version_id;
    private BigInteger dependency_package_name_id;
    private String dependency_constraint;
    private int lower_bound_number;
    private int upper_bound_number;
    
    public Dependency(BigInteger parent_version_id, BigInteger dependency_package_name_id, String dependency_constraint,
            int lower_bound_number, int upper_bound_number) {
        this.parent_version_id = parent_version_id;
        this.dependency_package_name_id = dependency_package_name_id;
        this.dependency_constraint = dependency_constraint;
        this.lower_bound_number = lower_bound_number;
        this.upper_bound_number = upper_bound_number;
    }

    public BigInteger getParent_version_id() {
        return parent_version_id;
    }

    public void setParent_version_id(BigInteger parent_version_id) {
        this.parent_version_id = parent_version_id;
    }

    public BigInteger getDependency_package_name_id() {
        return dependency_package_name_id;
    }

    public void setDependency_package_name_id(BigInteger dependency_package_name_id) {
        this.dependency_package_name_id = dependency_package_name_id;
    }

    public String getDependency_constraint() {
        return dependency_constraint;
    }

    public void setDependency_constraint(String dependency_constraint) {
        this.dependency_constraint = dependency_constraint;
    }

    public int getLower_bound_number() {
        return lower_bound_number;
    }

    public void setLower_bound_number(int lower_bound_number) {
        this.lower_bound_number = lower_bound_number;
    }

    public int getUpper_bound_number() {
        return upper_bound_number;
    }

    public void setUpper_bound_number(int upper_bound_number) {
        this.upper_bound_number = upper_bound_number;
    }

    
    

}
