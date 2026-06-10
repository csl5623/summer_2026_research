CREATE DATABASE vulnerability_tracking;

DROP TABLE vulnerability_tracking.package_metadata;

DROP TABLE vulnerability_tracking.package_metadata;

CREATE TABLE vulnerability_tracking.package_metadata(
    ID BIGINT PRIMARY KEY,
    name VARCHAR(255),
    version text,
    is_deprecated BOOL,
    upload_time DATE
);

select count(*) from vulnerability_tracking.package_metadata;
TRUNCATE TABLE package_dependencies;
TRUNCATE TABLE package_metadata;
DROP TABLE vulnerability_tracking.package_requirements;
CREATE TABLE vulnerability_tracking.package_requirements(
    ID BIGINT PRIMARY KEY AUTO_INCREMENT,
    package_id BIGINT,
    requirement text,
    FOREIGN KEY (package_id) REFERENCES vulnerability_tracking.package_metadata(ID)
);

select count(*) from vulnerability_tracking.package_requirements
TRUNCATE TABLE vulnerability_tracking.package_metadata
TRUNCATE TABLE vulnerability_tracking.package_requirements;

select * from vulnerability_tracking.package_metadata;

SELECT name,version,r.requirement FROM
vulnerability_tracking.package_metadata
JOIN vulnerability_tracking.package_requirements r on package_metadata.ID = r.package_id
WHERE name = "envdrift"
GROUP by name,version,r.requirement;




CREATE table dependencies(
    ID int PRIMARY KEY,
    dependency_package_id int,
    package_id int
);

CREATE table vulnerabilities(
    ID int PRIMARY KEY,
    package_id int,
    vulnerability_id int
);



CREATE table vulnerability_detail(
    ID int PRIMARY KEY,
    summary VARCHAR(255),
    details VARCHAR(255),
    introduced DATE,
    fixed_in DATE
)




