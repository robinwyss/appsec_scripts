# Python scripts to export useful information using the Dynatrace APIs

## Prerequisits
- Python 3
- [pandas](https://pypi.org/project/pandas/) and [requests](https://pypi.org/project/requests/) libraries. On Windows, windows-curses is required as well
  - pip install pandas
  - pip install requests
  - [Windows only] pip install windows-curses
- Dynatrace API Token with Read Entities (`entities.read`) and Read Security Problems (`securityProblems.read`) scope (for *processes_reporting_libraries.py* `DataExport` and `events.read` are required as well) 

## Available scripts
- [Export Vulnerabilities](#export_vulnerabilitiespy)
  - Exports a list of all vulnerabilities to a CSV file
- [Software Components for Process Group Instance](#softwareComponents4pgipy)
  - Retrieves all software components (libraries) for a specific process group instance
- [Libraries grouped by host and process](#libraries_by_hostpy)
  - Exports all libraries (optionally with vulnberabilities) grouped by host and process to a CSV
- [Vulnerabilities grouped by host and process](#vulnerabilities_by_hostpy)
  - Exports all  vulnerabilities grouped by host and process to a CSV
- [Processes reporting libraries ](#processes_reporting_librariespy)
  - Generates a list of all processes that are reporting software components and exports to a CSV
-  [attack_details](#attack_detailspy)
  - Exports a list of all attacks with details about the impacted container

## Usage

### [export_vulnerabilities.py](export_vulnerabilities.py)
exports all vulnerabilites to a CSV file

Required token scope: Read security problems (`securityProblems.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)                  
-d, --details                       Fetch the details for each security problem (takes longer)
```

#### Examples
```bash
python3 export_vulnerabilities.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Additionaly fetch details for each vulnerability
```bash
python3 export_vulnerabilities.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -d
```

### [softwareComponents4pgi.py](softwareComponents4pgi.py)
Exports all Software Components for a given Process Group Instance

Required token scope: Read entities (`entities.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)                  
-i PGIID, --id PGIID                The ID of the Process Group Instance for which libraries should be retrieved
```

#### Examples
```bash
python3 softwareComponents4pgi.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -id PROCESS_GROUP_INSTANCE_XXX
```

### [libraries_by_host.py](libraries_by_host.py)
Exports a list of all hosts with information about processes and libraries

Required token scope: Read entities (`entities.read`) and Read security problems (`securityProblems.read`) if the -v flag is used

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)     
-l LIBRARY, --library LIBRARY       Filter resulsts by a specific library (e.g. org.apache.logging.log4j), matches the libraries with a startsWith
-v, --vulnerabilities               Flag specifying if the vulnerabilites for each library should be retrieved  
-i, --hostIds                       Optional parameter to specify the hostIds for which the information should be retrieved (if ommited all hosts will be included). Multiple IDs can be specified, sparated by ',' (no spaces)               
```

#### Examples
Retrieve all libraries from all hosts
```bash
python3 libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Filter by a specific library (e.g. log4j)
```bash
python3 libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -l org.apache.logging.log4j
```

### [vulnerabilities_by_host.py](vulnerabilities_by_host.py)
Exports a list of all hosts with information about processes and vulnerabilities

Required token scope: Read entities (`entities.read`) and Read security problems (`securityProblems.read`) if the -v flag is used

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)     
-i, --hostIds                       Optional parameter to specify the hostIds for which the information should be retrieved (if ommited all hosts will be included). Multiple IDs can be specified, sparated by ',' (no spaces)
-s, --since                         If specified, only the vulnerabilities that were first seen since the specified number of hours are shown (e.g. -s 24 will only return the vulnerabilities that were detected in the last 24h)               
```

#### Examples
Retrieve all vulnerabilities from all hosts
```bash
python3 vulnerabilities_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```

### [processes_reporting_libraries.py](processes_reporting_libraries.py)
Exports a list of all hosts with information about processes and if they report any library. By default only the hosts and processes that report libraries are exported, but with the -a flag all hosts and processes are exported.

Required token scope: Read entities (`entities.read`) / Access problem and event feed, metrics, and topology (`DataExport`) / Read events (`events.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)     
-a, --all                           Prints all processes, even the ones that don't report libraries
-i, --hostIds                       Optional parameter to specify the hostIds for which the information should be retrieved (if ommited all hosts will be included). Multiple IDs can be specified, sparated by ',' (no spaces)               
```

#### Examples
Retrieve hosts and processes that report libraries. 
```bash
python3 processes_reporting_libraries.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Retrieve all hosts and processes, whether the process reports any libraries is defined in the last colument: (Y)es / (N)o
```bash
python3 processes_reporting_libraries.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -a
```

### [softwareComponents.py](softwareComponents.py)
Exports a list of all software components (libraries) with information about processes that use them. 

Required token scope: Read entities (`entities.read`) / Access problem and event feed, metrics, and topology (`DataExport`) / Read events (`events.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)     
-n, --name                          The name of the library to export, the name pattern is groupid:artifactid:version (for java) and it matches the begining of the name (startsWith).               
```

#### Examples
Retrieve all processes using snakeyaml
```bash
python3 processes_reporting_libraries.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -n org.yaml:snakeyaml
```

### [attack_details.py](attack_details.py)
Exports a list of all all attacks with details about the affected container

Required token scope: Read entities (`entities.read`) / Read attacks (`attacks.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)                    
```

#### Examples
Retrieve all processes using snakeyaml
```bash
python3 processes_reporting_libraries.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -n org.yaml:snakeyaml
```

## Logging
Logs are written to `output.log`, by default the log level is set to INFO, but it can be [changed to DEBUG](#set-log-level-to-debug)

## Additional parameters

### Skip SSL certificate validation
If your environment doesn't have a valid SSL certificate, you can skip the certificate validation with the following flag
> I am not going to lecture you on the importance of using SSL certificates here, you know the drill. 
```
-k , --insecure   Skip SSL certificate validation       
```

### Set log level to DEBUG
By default the log level is set to INFO, it can be changed to debug with the following flag:
> On DEBUG, the full response for each request is logged.
```
--debug   Sets the log level to debug
```
