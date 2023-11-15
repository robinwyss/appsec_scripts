#!/usr/bin/env python
from curses import meta
import sys
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi
import logging
import logging.config
import time
import re


def getProperty(entity, propertyName):
    """
    Retrieves the value of a property from an entity if it exists, otherwise an empty string
    param: dictionary entity: the entity from which the property should be retrieved
    param: string propertyName: the property to be retrieved
    return: string: the value of the property or empty string if it doesn' exist.
    """
    if propertyName in entity['properties']:
        return entity['properties'][propertyName]
    else:
        return ""

def getMetadata(entity, propertyName):
    """
    Retrieves the value of a property from an entity if it exists, otherwise an empty string
    param: dictionary entity: the entity from which the property should be retrieved
    param: string propertyName: the property to be retrieved
    return: string: the value of the property or empty string if it doesn' exist.
    """
    metadata = getProperty(entity, 'metadata')
    if property:
        for entry in metadata:
            if entry['key'] == propertyName:
                return entry['value']
    return ""

def getCmdPath(process):
    processType = getProperty(process,'processType' )
    if processType == 'JAVA':
        return getMetadata(process, 'JAVA_JAR_PATH')
    elif processType == 'DOTNET':
        return getMetadata(process, 'DOTNET_COMMAND_PATH')
    elif processType == 'NODE_JS':
        return getMetadata(process, 'NODE_JS_SCRIPT_NAME')
    else:
        return ""
#added host[managementzone] SRS
def fieldsToPrint(host, process, securityProblem):
    cve = ''
    if 'cveIds' in securityProblem:
        cve = ''.join(securityProblem['cveIds'])
    if 'baseRiskLevel' in securityProblem['riskAssessment']:
        baseRiskLevel = securityProblem['riskAssessment']['baseRiskLevel']
        baseRiskScore = securityProblem['riskAssessment']['baseRiskScore']
    else:
        # if there is no base risk score and level, it is the same as the risk level (DSS). This is the case for CLVs
        baseRiskLevel = securityProblem['riskAssessment']['riskLevel']
        baseRiskScore = securityProblem['riskAssessment']['riskScore']

    externalId = securityProblem['externalVulnerabilityId'];
    if externalId.startswith('SNYK'):
        extUrl = 'https://snyk.io/vuln/'+externalId
    else:
        extUrl = 'https://nvd.nist.gov/vuln/detail/' + externalId
    
        
    return [host['displayName'],
        host['entityId'],
       # host['managementZones'],
        process['displayName'],
        process['entityId'],
        getProperty(process, 'jvmClrVersion'),
        securityProblem.get('packageName', ''),
        cve,
        securityProblem['title'],
        securityProblem['displayId'],
        securityProblem['url'],
        extUrl,
        securityProblem['riskAssessment']['riskLevel'],
        securityProblem['riskAssessment']['riskScore'],
        baseRiskLevel,
        baseRiskScore,
        securityProblem['riskAssessment']['exposure'],
        securityProblem['riskAssessment']['dataAssets'],
        securityProblem['riskAssessment']['publicExploit'],
        securityProblem['riskAssessment']['vulnerableFunctionUsage'],
        securityProblem['vulnerabilityType'],
        getMetadata(process, 'EXE_PATH'),
        getMetadata(process, 'COMMAND_LINE_ARGS'), 
        getCmdPath(process)
        ]

start_time = time.time()

# get the Dynatrace Environmemnt (URL) and the API Token and default parameters
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')
# additional parameter
parser.add_argument("-i", "--hostIds", dest="hostIds", help="Specify the host ids for which the data should be retrieved", required=False)

args = parser.parse_args()

env = args.environment
apiToken = args.token
hostIds = args.hostIds
verifySSL = not args.insecure
debug = args.debug

#if debug:
logging.getLogger().setLevel(logging.DEBUG)

logging.basicConfig(filename='output.log', level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("="*200)
logging.info("Running %s ", re.sub(r"dt0c01\.[\S]+","dt0c01.XXX"," ".join(sys.argv)))
logging.info("="*200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

with open('vulnerabilities_by_host.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=";", quoting=csv.QUOTE_ALL)
    # header
    #added host.mz SRS
    header = ['host.name', 'host.id', 'process.name', 'process.id', 'process.technologyVersion', 'library.packageName', 'cve','title','displayId','Dynatrace Link','External Link','DSS-level', 'DSS-score', 'CVSS-level', 'CVSS-score','Public Exposure','Reachable Data', 'Exploit','Vulnerable Function','Type','Exe Path', 'Commandline args', 'Command path']
    writer.writerow(header)

    if hostIds:
        hosts = dynatraceApi.getHostsById(hostIds)
    else: 
        hosts = dynatraceApi.getHosts()
    for host in hosts:
        if 'isProcessOf' in host['toRelationships']:
            processReferences = host['toRelationships']['isProcessOf']
            processes = dynatraceApi.getProcesses(processReferences)
            for process in processes:
                process_group_id = process['fromRelationships']['isInstanceOf'][0]['id']
                securityProblems = dynatraceApi.getSecurityProblemsForProcessGroup(process_group_id)
                for securityProblem in securityProblems:
                    fields = fieldsToPrint(host, process, securityProblem)
                    writer.writerow(fields)

end_time=time.time()
print('')
print(f'Script completed successfully, took {(end_time-start_time):.2f}s')
