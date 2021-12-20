# Python scripts to export useful information using the Dynatrace APIs

### [export_vulnerabilities.py](export_vulnerabilities.py)
exports all vulnerabilites to a CSV file
##### Examples
```bash
libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Additionaly fetch details for each vulnerability
```bash
libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -d
```

### [softwareComponents4pgi.py](softwareComponents4pgi.py)
Exports all Software Components for a given Process Group Instance
##### Examples
```bash
libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -id PROCESS_GROUP_INSTANCE_XXX
```

### [libraries_by_host.py](libraries_by_host.py)
Exports a list of all hosts with information about processes and libraries

##### Examples
Retrieve all libraries from all hosts
```bash
libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Filter by a specific library (e.g. log4j)
```bash
libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -l org.apache.logging.log4j
```