#!/usr/bin/env python
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-i", "--hostIds", dest="hostIds", help="Specify the host ids for which the data should be retrieved", required=False)
parser.add_argument("-a", "--all", dest="all", help="Prints all processes, even the ones that don't report libraries", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
hostIds = args.hostIds
printall = args.all
verifySSL = not args.insecure

processType = ['JAVA', 'DOTNET', 'NODE_JS', 'PHP']

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

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


def fieldsToPrint(host, process):
    return [host['displayName'],
        host['entityId'],
        process['displayName'],
        process['entityId'],
        getTechnologyVersion(process)]

with open('processes_reporting_libs.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['host.name', 'host.id', 'process.name', 'process.id', 'process.technologyVersion', 'reportedLibs']
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
                if 'processType' in process['properties']:
                    if 'isSoftwareComponentOfPgi' in process['toRelationships']:
                        fields = fieldsToPrint(host, process)
                        fields += ['Y']
                        writer.writerow(fields)
                    elif printall:
                        fields = fieldsToPrint(host, process)
                        fields += ['N']
                        writer.writerow(fields)
