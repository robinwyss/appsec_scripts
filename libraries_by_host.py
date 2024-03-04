#!/usr/bin/env python
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

def fieldsToPrint(host, process, softwareComponent):
    return [host['displayName'],
        host['entityId'],
        process['displayName'],
        process['entityId'],
        getProperty(process, 'jvmClrVersion'),
        softwareComponent['displayName'],
        softwareComponent['entityId'],
        getProperty(softwareComponent, 'softwareComponentShortName'),
        getProperty(softwareComponent,'softwareComponentFileName'),
        getProperty(softwareComponent,'packageName')]

def fieldsToPrintForVulnerabilities(securityProblem):
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
    return [
        cve,
        securityProblem['title'],
        securityProblem['displayId'],
        securityProblem['url'],
        securityProblem['riskAssessment']['riskLevel'],
        securityProblem['riskAssessment']['riskScore'],
        baseRiskLevel,
        baseRiskScore
        ]

start_time=time.time()

# get the Dynatrace Environmemnt (URL) and the API Token and default parameters
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')
# additional parameter
parser.add_argument("-l", "--library", dest="library", help="Filter resulsts by a specific library", required=False)
parser.add_argument("-v", "--vulnerabilities", dest="vulnerabilities", help="Get the vulnerabilities for each Software Component", action='store_true')
parser.add_argument("-i", "--hostIds", dest="hostIds", help="Specify the host ids for which the data should be retrieved", required=False)

args = parser.parse_args()

env = args.environment
apiToken = args.token
includeVulnerabilities = args.vulnerabilities
hostIds = args.hostIds
verifySSL = not args.insecure
libraryToFilterBy = args.library
debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("="*200)
logging.info("Running %s ", re.sub(r"dt0c01\.[\S]+","dt0c01.XXX"," ".join(sys.argv)))
logging.info("="*200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

with open('libraries_by_host.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_ALL)
    # header
    header = ['host.name', 'host.id', 'process.name', 'process.id', 'process.technologyVersion', 'library.name', 'library.id', 'library.shortName', 'library.fileName','library.packageName']
    if includeVulnerabilities:
        header += ['cve','title','displayId','url', 'DSS-level', 'DSS-score', 'CVSS-level', 'CVSS-score']
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
                if 'processType' in process['properties'] and 'isSoftwareComponentOfPgi' in process['toRelationships']:
                    softwareComponentRefs = process['toRelationships']['isSoftwareComponentOfPgi']
                    softwareComponents = dynatraceApi.getSoftwareComponentDetails(softwareComponentRefs)
                    if libraryToFilterBy:
                        softwareComponents = filter(lambda e: e['displayName'].startswith(libraryToFilterBy), softwareComponents)
                    for softwareComponent in softwareComponents:
                        fields = fieldsToPrint(host, process, softwareComponent)
                        if includeVulnerabilities:
                            securityProblems = dynatraceApi.getSecurityProblemsForSoftwareComponent(softwareComponent['entityId'])
                            for securityProblem in securityProblems:
                                securityProblemFields = fieldsToPrintForVulnerabilities(securityProblem)
                                writer.writerow(fields + securityProblemFields)
                        else:
                            writer.writerow(fields)

end_time=time.time()
print('')
print(f'Script completed successfully, took {(end_time-start_time):.2f}s')