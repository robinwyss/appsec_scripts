#!/usr/bin/env python
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-l", "--library", dest="library", help="Filter resulsts by a specific library", required=False)
parser.add_argument("-v", "--vulnerabilities", dest="vulnerabilities", help="Get the vulnerabilities for each Software Component", action='store_true')
parser.add_argument("-i", "--hostIds", dest="hostIds", help="Specify the host ids for which the data should be retrieved", required=False)

args = parser.parse_args()

env = args.environment
apiToken = args.token
includeVulnerabilities = args.vulnerabilities
hostIds = args.hostIds

libraryToFilterBy = args.library
processType = ['JAVA', 'DOTNET']

dynatraceApi = DynatraceApi(env, apiToken)

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

def getTechnologyVersion(process):
    """
    Gets the technology information from a process
    param: dictionary entity: the process entity from which the information should be retrieved
    return string: technology version
    """
    softwareTechnologies = getProperty(process, 'softwareTechnologies')
    for technology in softwareTechnologies:
        if technology['type'] == processType and 'version' in technology:
            version = technology['version']
            if 'edition' in technology:
                version += " ("+technology['edition']+")"
            return version


def fieldsToPrint(host, process, softwareComponent):
    return [host['displayName'],
        host['entityId'],
        process['displayName'],
        process['entityId'],
        getTechnologyVersion(process),
        softwareComponent['displayName'],
        softwareComponent['entityId'],
        getProperty(softwareComponent, 'softwareComponentShortName'),
        getProperty(softwareComponent,'softwareComponentFileName'),
        getProperty(softwareComponent,'packageName')]

def fieldsToPrintForVulnerabilities(securityProblem):
    cve = ''.join(securityProblem['cveIds'])
    return [
        cve,
        securityProblem['title'],
        securityProblem['displayId'],
        securityProblem['url']
        ]

with open('libraries_by_host.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['host.name', 'host.id', 'process.name', 'process.id', 'process.technologyVersion', 'library.name', 'library.id', 'library.shortName', 'library.fileName','library.packageName']
    if includeVulnerabilities:
        header += ['cve','title','displayId','url']
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
