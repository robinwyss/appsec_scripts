# Python scripts to export useful information using the Dynatrace APIs

## Prerequisits
- Python 3
- Dynatrace API Token with Read Entities (`entities.read`) and Read Security Problems (`securityProblems.read`) scope 



### [export_vulnerabilities.py](export_vulnerabilities.py)
exports all vulnerabilites to a CSV file

Required token scope: Read security problems (`securityProblems.read`)

##### Examples
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

##### Examples
```bash
python3 softwareComponents4pgi.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -id PROCESS_GROUP_INSTANCE_XXX
```

### [libraries_by_host.py](libraries_by_host.py)
Exports a list of all hosts with information about processes and libraries

Required token scope: Read entities (`entities.read`)

##### Examples
Retrieve all libraries from all hosts
```bash
python3 libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... 
```
Filter by a specific library (e.g. log4j)
```bash
python3 libraries_by_host.py -e https://xxxyyyyy.live.dynatrace.com -t dt0c01.XXX... -l org.apache.logging.log4j
```
