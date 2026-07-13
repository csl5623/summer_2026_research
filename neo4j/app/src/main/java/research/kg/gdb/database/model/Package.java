package research.kg.gdb.database.model;

import java.math.BigInteger;
import java.sql.Time;
import java.sql.Timestamp;

public class Package {

    private int id;
    private String name;
    private boolean isDeleted;
    private Timestamp upload_time;

    public Package(int id, String name, boolean isDeleted, Timestamp upload_time) {
        this.id = id;
        this.name = name;
        this.isDeleted = isDeleted;
        this.upload_time = upload_time;

    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isDeleted() {
        return isDeleted;
    }

    public void setDeleted(boolean isDeleted) {
        this.isDeleted = isDeleted;
    }

    public Timestamp getUpload_time() {
        return upload_time;
    }

    public void setUpload_time(Timestamp upload_time) {
        this.upload_time = upload_time;
    }

}
