#!/usr/bin/env python
import sys
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi
import logging
import logging.config
from datetime import datetime
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

parser.add_argument("-i", "--hostIds", dest="hostIds", help="Specify the host ids for which the data should be retrieved", required=False)
parser.add_argument("-a", "--all", dest="all", help="Prints all supported processes, even the ones that don't report libraries", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
hostIds = args.hostIds
printall = args.all
verifySSL = not args.insecure
debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

processTypes = ['DOTNET', 'IIS_APP_POOL', 'JAVA', 'NODE_JS', 'PHP']

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
    technologies = ""
    for technology in softwareTechnologies:
        if 'version' in technology:
            version = technology['version']
            if 'edition' in technology:
                version += " ("+technology['edition']+")"
        else:
            version = ""
        technologies += technology['type']  + version +' | '
    return technologies


def fieldsToPrint(host, process):
    return [host['displayName'],
        host['entityId'],
        process['displayName'],
        process['entityId'],
        getProperty(process, 'processType')]

def timeStampToDate(timestamp):
    return datetime.utcfromtimestamp(timestamp / 1000).strftime('%Y-%m-%d %H:%M:%S')

def getLatestRestart(processId):
    response = dynatraceApi.getRestartEvents(processId)
    if len(response['events']) > 0:
        return timeStampToDate(response['events'][0]['endTime'])
    else:
        "-"

def getFields(host, process, count):
    lastRestart = getLatestRestart(process['entityId'])
    processInfoV1 = dynatraceApi.getProcessV1(process['entityId'])
    firstSeen = timeStampToDate(processInfoV1['firstSeenTimestamp'])
    lastSeen = timeStampToDate(processInfoV1['lastSeenTimestamp'])

    fields = fieldsToPrint(host, process)
    fields += ['Y' if count > 0 else 'N', count]
    fields += [lastRestart, firstSeen, lastSeen,
        getProperty(process, 'installerVersion'), getProperty(host, 'memoryTotal'), getProperty(host, 'monitoringMode')]
    return fields

with open('processes_reporting_libs.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['host.name', 'host.id', 'process.name', 'process.id', 'process.type', 'reportedLibs', 'nbrOfLibs', 'lastRestart', 'firstSeen', 'lastSeen','agentVersion','memoryTotal','monitoringMode']
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
                if 'processType' in process['properties'] and getProperty(process, 'processType') in processTypes:
                    if 'isSoftwareComponentOfPgi' in process['toRelationships']:
                        sc_count = len(process['toRelationships']['isSoftwareComponentOfPgi'])
                        fields = getFields(host, process, sc_count)
                        writer.writerow(fields)
                    elif printall:
                        fields = getFields(host, process, 0)
                        writer.writerow(fields)
