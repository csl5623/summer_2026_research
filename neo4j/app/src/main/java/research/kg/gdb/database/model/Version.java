package research.kg.gdb.database.model;

import java.math.BigInteger;

public class Version {
    
    private int id;
    private int package_name_id;
    private String string_version;
    private int MAJOR;
    private int MINOR;
    private int MICRO;
    private int sequence_order;


    public Version(int id, int package_name_id,String string_version, int MAJOR, int minor, int micro, int sequence_order){
        this.id = id;
        this.package_name_id = package_name_id;
        this.string_version = string_version;
        this.MAJOR = MAJOR;
        this.MICRO =micro;
        this.MINOR= minor;
        this.sequence_order = sequence_order;
    }

    public int getId() {
        return id;
    }
    public void setId(int id) {
        this.id = id;
    }
    public int getPackage_name_id() {
        return package_name_id;
    }
    public void setPackage_name_id(int package_name_id) {
        this.package_name_id = package_name_id;
    }
    public String getString_version() {
        return string_version;
    }
    public void setString_version(String string_version) {
        this.string_version = string_version;
    }
    public int getMAJOR() {
        return MAJOR;
    }
    public void setMAJOR(int mAJOR) {
        MAJOR = mAJOR;
    }
    public int getMINOR() {
        return MINOR;
    }
    public void setMINOR(int mINOR) {
        MINOR = mINOR;
    }
    public int getMICRO() {
        return MICRO;
    }
    public void setMICRO(int mICRO) {
        MICRO = mICRO;
    }
    public int getSequence_order() {
        return sequence_order;
    }
    public void setSequence_order(int sequence_order) {
        this.sequence_order = sequence_order;
    }
    
    
}
