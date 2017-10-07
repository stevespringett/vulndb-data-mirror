[![Build Status](https://travis-ci.org/stevespringett/vulndb-data-mirror.svg?branch=master)](https://travis-ci.org/stevespringett/vulndb-data-mirror)

VulnDB Data Mirror
================

A simple Java command-line utility to mirror the entire contents of the [VulnDB] service from [Risk Based Security].

The intended purpose of vulndb-data-mirror is to be able to replicate the VulnDB vulnerabiity 
data inside a company firewall so that local (faster) access to data can be achieved and reused 
by the [OWASP Dependency-Check] and [OWASP Dependency-Track] ecosystem.

The VulnDB service utilizes a paginated REST API that must be walked for each type of feed. 
Due to the large data-set the service provides, it may take an hour or more to mirror the contents. 
Because of the performance impact due to this design, a separate mirroring utility is favorable
instead of native VulnDB mirroring support in Dependency-Check or Dependency-Track.
VulnDB Data Mirror serves this purpose.

For best results, use vulndb-data-mirror with cron or another scheduler to keep the mirrored data fresh.

A subscription to VulnDB is required for use. Contact [VulnDB] for evaluation and 
subscription information.

Usage
----------------

### Building

```sh
mvn clean package
```

### Running

```sh
java -jar vulndb-data-mirror.jar <mirror-directory>
```

Downloading
----------------

If you do not wish to download sources and compile yourself, [pre-compiled binaries] are available 
for use. VulnDB Data Mirror is also available on the Maven Central Repository.

```xml
<dependency>
    <groupId>us.springett</groupId>
    <artifactId>vulndb-data-mirror</artifactId>
    <version>1.0.0-SNAPSHOT</version>
</dependency>
```

Related Projects
----------------

* [NIST Data Mirror](https://github.com/stevespringett/nist-data-mirror)

Copyright & License
-------------------

vulndb-data-mirror is Copyright (c) Steve Springett. All Rights Reserved.

Dependency-Track is Copyright (c) Steve Springett. All Rights Reserved.

Dependency-Check is Copyright (c) Jeremy Long. All Rights Reserved.

VulnDB is Copyright (c) Risk Based Security. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE] [Apache 2.0] file for the full license.

  [OWASP Dependency-Check]: https://www.owasp.org/index.php/OWASP_Dependency_Check
  [OWASP Dependency-Track]: https://www.owasp.org/index.php/OWASP_Dependency_Track_Project
  [Apache 2.0]: https://github.com/stevespringett/vulndb-data-mirror/blob/master/LICENSE
  [pre-compiled binaries]: https://github.com/stevespringett/vulndb-data-mirror/releases
  [VulnDB]: https://vulndb.cyberriskanalytics.com/
  [Risk Based Security]: https://www.riskbasedsecurity.com/ 