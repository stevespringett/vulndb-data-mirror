[![Build Status](https://travis-ci.org/stevespringett/vulndb-data-mirror.svg?branch=master)](https://travis-ci.org/stevespringett/vulndb-data-mirror)

VulnDB Data Mirror
================

A simple Java command-line utility to mirror the entire contents of the [VulnDB] service from [Risk Based Security].

The intended purpose of vulndb-data-mirror is to be able to replicate the VulnDB vulnerabiity 
data inside a company firewall so that local (faster) access to data can be achieved.

In addition to mirroring functionality, VulnDB Data Mirror includes a parser that can automatically
convert JSON data to model objects (defined as POJO's). This greatly eases the ramp-up time needed
to consume the VulnDB data in a programmatic way.

The VulnDB service utilizes a paginated REST API that must be walked for each type of feed. 
Due to the large data-set the service provides, it may take an hour or more to mirror the contents. 

For best results, use vulndb-data-mirror with cron or another scheduler to keep the mirrored data fresh.

A subscription to VulnDB is required for use. Contact [VulnDB] for evaluation and subscription information. 
VulnDB Data Mirror or it's creator are not affiliated with VulnDB or Risk Based Security. This is a 
community-driven project that acknowledges the value of third-party vulnerability intelligence to 
enhance or supplement publicly disclosed information.

By using VulnDB Data Mirror, you accept that it will be used in a manner that conforms to the VulnDB terms of service.


Distribution
----------------

VulnDB Data Mirror is distributed two different ways. 


[Pre-compiled binaries] WILL be available (once 1.0.0 is released) from GitHub. This distribution
is intended to be extracted and executed in order to run and maintain a working VulnDB mirror. This is the
recommended method for most users.


The standalone library is available in the Maven Central 
Repository. This distribution is useful for programmatic access to the mirroring or parsing functionality.


```xml
<dependency>
    <groupId>us.springett</groupId>
    <artifactId>vulndb-data-mirror</artifactId>
    <version>1.0.0</version>
</dependency>
```


Usage
----------------

### Windows


```sh
vulndb-data-mirror.bat --consumer-key mykey --consumer-secret mysecret --dir "c:\path\to\mirror"
```


### Unix/Linux

```sh
vulndb-data-mirror.sh --consumer-key mykey --consumer-secret mysecret --dir "/path/to/mirror"
```

When running, the console output will resemble:

```
VulnDB API Status:
--------------------------------------------------------------------------------
Organization Name.............: Example Inc.
Name of User Requesting.......: Jane Doe
Email of User Requesting......: jane@example.com
Subscription Expiration Date..: 2018-12-31
API Calls Allowed per Month...: 25000
API Calls Made This Month.....: 1523
--------------------------------------------------------------------------------

Mirroring Vendors feed...
  Processing 18344 of 18344 results
Mirroring Products feed...
  Processing 136853 of 136853 results
Mirroring Vulnerabilities feed...
  Processing 142500 of 166721 results
```

### Getting Help

Execute vulndb-data-mirror.bar or vulndb-data-mirror.sh (without options)
```
usage: vulndb-data-mirror
    --consumer-key <key>          The Consumer Key provided by VulnDB
    --consumer-secret <secret>    The Consumer Secret provided by VulnDB
    --dir <dir>                   The target directory to store contents
 -prod,--mirror-products          Mirror the products data feed
 -vend,--mirror-vendors           Mirror the vendors data feed
 -vuln,--mirror-vulnerabilities   Mirror the vulnerabilities data feed
 -stat,--status-only              Displays VulnDB API status only
```

### Mirror Recovery

VulnDB Data Mirror can recover from several types of errors. Upon a successful request to VulnDB, this utility 
will store a timestamp and the last successful page number processed. Pagination of VulnDB defaults to retrieving 
100 records at a time. In the event of a network or service error, it is possible to start again where the mirroring 
left off.

This information is stored in `update.properties` located in the specified mirror directory.

### VulnDB API License

The process of mirroring the contents of VulnDB takes several thousand requests. You may estimate the number of 
requests required by dividing 100 by the total number of results in each of the three feeds. After mirroring is 
complete, make a backup of the contents so that a full mirror does not have to take place again. VulnDB may be 
licensed based on the number of API calls made to the service. Check with the vendor for details.


Compiling
----------------

```bash
mvn clean package
```


Related Projects
----------------

* [NIST Data Mirror](https://github.com/stevespringett/nist-data-mirror)

Copyright & License
-------------------

vulndb-data-mirror is Copyright (c) Steve Springett. All Rights Reserved.

VulnDB is Copyright (c) Risk Based Security. All Rights Reserved.

Permission to modify and redistribute is granted under the terms of the Apache 2.0 license. See the [LICENSE] [Apache 2.0] file for the full license.

  [Apache 2.0]: https://github.com/stevespringett/vulndb-data-mirror/blob/master/LICENSE
  [Pre-compiled binaries]: https://github.com/stevespringett/vulndb-data-mirror/releases
  [VulnDB]: https://vulndb.cyberriskanalytics.com/
  [Risk Based Security]: https://www.riskbasedsecurity.com/ 
