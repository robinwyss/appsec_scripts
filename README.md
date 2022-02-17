# Python scripts to export useful information using the Dynatrace APIs

## Prerequisits
- Python 3
- [pandas](https://pypi.org/project/pandas/) and [requests](https://pypi.org/project/requests/) libraries
  - pip install pandas
  - pip install requests
- Dynatrace API Token with Read Entities (`entities.read`) and Read Security Problems (`securityProblems.read`) scope 

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
-i, --hostIds                       Optional flat to specify the hostIds for which the information should be retrieved (if ommited all hosts will be included). Multiple IDs can be specified, sparated by ',' (no spaces)               
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

### [processes_reporting_libraries.py](processes_reporting_libraries.py)
Exports a list of all hosts with information about processes and if they report any library. By default only the hosts and processes that report libraries are exported, but with the -a flag all hosts and processes are exported.

Required token scope: Read entities (`entities.read`)

#### Arguments
```
-e ENVIRONMENT, --env ENVIRONMENT   The Dynatrace Environment to use (e.g. https://xxxyyyyy.live.dynatrace.com)                    
-t TOKEN, --token TOKEN             The Dynatrace API Token to use (e.g. dt0c01.XXX...)     
-a, --all               Prints all processes, even the ones that don't report libraries
-i, --hostIds                       Optional flat to specify the hostIds for which the information should be retrieved (if ommited all hosts will be included). Multiple IDs can be specified, sparated by ',' (no spaces)               
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

## Additional parameters

### Skip SSL certificate validation
If your environment doesn't have a valid SSL certificate, you can skip the certificate validation with the following flag
> I am not going to lecture you on the importance of using SSL certificates here, you know the drill. 
```
-k , --insecure   Skip SSL certificate validation       
```