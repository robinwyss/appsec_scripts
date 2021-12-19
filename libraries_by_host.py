#!/usr/bin/env python
import requests
from argparse import ArgumentParser
import functools
import csv

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)

args = parser.parse_args()

env = args.environment
apiToken = args.token
processType = 'JAVA'

def getSoftwareComponents(softwareComponents):
    return getAllEntitiesByIDs('/api/v2/entities?fields=fromRelationships,properties.packageName,properties.softwareComponentFileName,properties.softwareComponentShortName,properties.softwareComponentType', softwareComponents)

def getProcesses(processes):
    return getAllEntitiesByIDs('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties.processType,properties.softwareTechnologies', processes)

def getHosts():
    return getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf&entitySelector=type("HOST")')

def getAllEntitiesByIDs(endpoint, entityRefs):
    entities = []
    listOfEntityIds = splitIntoChunks(entityRefs, 100)
    for entitieIds in listOfEntityIds:
        ids = getIdsFromEntities(entitieIds)
        entities += getAllEntities(endpoint + '&entitySelector=entityId('+ids+')')
    return entities

def getAllEntities(endpoint):
    entities = []
    response = queryApi(endpoint)
    entities += response["entities"]
    while("nextPageKey" in response):
        response = queryApi('/api/v2/entities?nextPageKey='+response["nextPageKey"])
        entities += response["entities"]
    return entities

def getIdsFromEntities(entities):
    return ','.join('"'+i['id']+'"' for i in entities)

# splits a list into of max length n
def splitIntoChunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def queryApi(endpoint):
    authHeader = {'Authorization' : 'Api-Token '+ apiToken}
    response = requests.get(env + endpoint, headers=authHeader)
    print('.', end="", flush=True) # print a dot for every call to show activity
    return response.json()

def getProperty(entity, propertyName):
    if propertyName in entity['properties']:
        return entity['properties'][propertyName]
    else:
        return ""

def getTechnologyVersion(process):
    softwareTechnologies = getProperty(process, 'softwareTechnologies')
    for technology in softwareTechnologies:
        if technology['type'] == processType and 'version' in technology:
            version = technology['version']
            if 'edition' in technology:
                version += " ("+technology['edition']+")"
            return version
    
with open('libraries_by_host.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    writer.writerow(['host.name', 'host.id', 'process.name', 'process.id', 'process.technologyVersion', 'library.name', 'library.id', 'library.shortName', 'library.fileName','library.packageName'])

    hosts = getHosts()
    for host in hosts:
        if 'isProcessOf' in host['toRelationships']:
            processReferences = host['toRelationships']['isProcessOf']
            processes = getProcesses(processReferences)
            for process in processes:
                if 'processType' in process['properties'] and process['properties']['processType'] == processType:
                    if 'isSoftwareComponentOfPgi' in process['toRelationships']:
                        softwareComponentRefs = process['toRelationships']['isSoftwareComponentOfPgi']
                        softwareComponents = getSoftwareComponents(softwareComponentRefs)
                        for softwareComponent in softwareComponents:
                            writer.writerow([
                                host['displayName'],
                                host['entityId'],
                                process['displayName'],
                                process['entityId'],
                                getTechnologyVersion(process),
                                softwareComponent['displayName'],
                                softwareComponent['entityId'],
                                getProperty(softwareComponent, 'softwareComponentShortName'),
                                getProperty(softwareComponent,'softwareComponentFileName'),
                                getProperty(softwareComponent,'packageName'),
                                ])
