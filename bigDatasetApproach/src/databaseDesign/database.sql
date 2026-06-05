CREATE TABLE vulnerability_tracking.package_metadata(
    ID BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    is_deprecated BOOL,
);

##parent_version_id, could have many requirements. so its 1: M
CREATE TABLE vulnerability_tracking.requirement(
    id PRIMARY KEY
    parent_version_id BIGINT,
    requirement VARCHAR
)

CREATE TABLE vulnerability_tracking.dependencies(
    parent_version_id BIGINT,
    dependency_package_version_id BIGINT
    PRIMARY KEY (parent_version_id,dependency_package_version_id)
)

CREATE TABLE vulnerability_tracking.package_versions(
    id BIGINT PRIMARY KEY
    package_id BIGINT FOREIGN KEY,
    upload_time DATETIME,
    string_version STRING
    MAJOR INT,
    MINOR INT,
    MICRO INT,
    PRE INT,
    POST INT,
    EPOCH INT
)

CREATE TABLE vulnerability_tracking.vulnerability(
    ID BIGINT PRIMARY KEY,
    name VARCHAR(255),
    summary VARCHAR(100),
    details TEXT,
    modified DATETIME
);

CREATE TABLE vulnerability_tracking.affected_packages(
    package_version_id BIGINT,
    vulnerability_id BIGINT,
    PRIMARY KEY (package_version_id, vulnerability_id),
)

CREATE TABLE vulnerability_tracking.vulnerability_range(
    id PRIMARY KEY
    vulnerability_id BIGINT FOREIGN KEY,
    introduced_pacakge_version_id BIGINT FOREIGN KEY,
    fixed_package_version_id BIGINT FOREIGN KEY
)