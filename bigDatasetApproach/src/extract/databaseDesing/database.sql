CREATE TABLE vulnerability_tracking.package_metadata(
    ID BIGINT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255),
    version VARCHAR(100)
);

CREATE TABLE vulnerability_tracking.package_requirements(
    PRIMARY KEY (package_id, requirement),
    package_id INT,
    requirement VARCHAR(1000),
    FOREIGN KEY (package_id) REFERENCES vulnerability_tracking.package_metadata(ID)
);

CREATE TABLE vulnerability_tracking.vulnerability(
    ID BIGINT PRIMARY KEY,
    name VARCHAR(255),
    summary VARCHAR(100),
    introduced VARCHAR(100),
    fixed_in VARCHAR(100)
);

CREATE TABLE vulnerability_tracking.dependencies(
    package_id BIGINT,
    dependency_id BIGINT (will refer to packaege_metadata to get the package id for that)
)

CREATE TABLE vulnerability_tracking.package_vulnerability(
    package_id BIGINT,
    vulnerability_id BIGINT
)

## Query to find direct vulnerabilities for a package

SELECT name,version, vulnerability_name
JOIN package_id table with package_vulnerability table to get 
JOIN package_vulnerabikity_table with vulnerabikity table to get vulnerability_name


## Query to find indirect vulnerabilities of a package

##get all dependencies for a package using the dependency table
##for all the dependencies, get the vulnerability_id by querying the package_vulnerability and get package vulnerabiities


##Query currently vulnerable packages

select from vulenrability tables the records with null in fixed in
and join with vulnerability packages table to get packages that have that vulnerabiities

##Query currently vulnerable packages

select from vulenrability tables the records with not null in fixed in
and join with vulnerability packages table to get packages that have that vulnerabiities