#!/usr/bin/env python
import requests
from argparse import ArgumentParser
import functools
import csv

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-l", "--library", dest="library", help="Filter resulsts by a specific library", required=False)

args = parser.parse_args()

env = args.environment
apiToken = args.token
libraryToFilterBy = args.library
processType = 'JAVA'

def getSoftwareComponents(softwareComponents):
    """
    Retrieves the details of the specfied software components
    :param list of entity references (dic) (e.g. [{'id': ...}])
    :return list of entities (dictionary)
    """
    return getAllEntitiesByIDs('/api/v2/entities?fields=fromRelationships,properties.packageName,properties.softwareComponentFileName,properties.softwareComponentShortName,properties.softwareComponentType', softwareComponents)

def getProcesses(processes):
    """
    Retrieves the details of the specfied processes, with thechnolgy details and the relations to software components
    :param list of entity references (dic) (e.g. [{'id': ...}])
    :return list of entities (dictionary)
    """
    return getAllEntitiesByIDs('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties.processType,properties.softwareTechnologies', processes)

def getHosts():
    """
    Get all hosts with the relationships to processes (PGIs)
    :return list of entities (dictionary)
    """
    return getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf&entitySelector=type("HOST")')

def getAllEntitiesByIDs(endpoint, entityRefs):
    """
    Retrieves all entities by the specified entity references.
    param: string endpoint: the API endpoint to call
    param: list entityRefs: entities to be retrieved
    return: list of entities (dictionary) 
    """
    entities = []
    # split the list into chunks of 100 in order to avoid too large requests (URI too long)
    listOfEntityIds = splitIntoChunks(entityRefs, 100)
    for entitieIds in listOfEntityIds:
        ids = getIdsFromEntities(entitieIds)
        entities += getAllEntities(endpoint + '&entitySelector=entityId('+ids+')')
    return entities

def getAllEntities(endpoint):
    """
    Retrieves all entities by the specified api call (handles paging of results)
    param: str endpoint: the API endpoint to call
    return: list of entities (dictionary) 
    """
    entities = []
    response = queryApi(endpoint)
    entities += response["entities"]
    while("nextPageKey" in response):
        response = queryApi('/api/v2/entities?nextPageKey='+response["nextPageKey"])
        entities += response["entities"]
    return entities

def getIdsFromEntities(entities):
    """
    Combines the IDs of the entities into a string to be used in an API call (e.g. '"ID1","ID2..."')
    param: list of entities
    return string
    """
    return ','.join('"'+i['id']+'"' for i in entities)

def splitIntoChunks(lst, n):
    """Yield successive n-sized chunks from lst."""
    for i in range(0, len(lst), n):
        yield lst[i:i + n]

def queryApi(endpoint):
    """
    Calls the given endpoint on the Dynatrace API. 
    param: string endpoint: API endpoint to be called
    return: response as json
    """
    authHeader = {'Authorization' : 'Api-Token '+ apiToken}
    response = requests.get(env + endpoint, headers=authHeader)
    print('.', end="", flush=True) # print a dot for every call to show activity
    return response.json()

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
                        if libraryToFilterBy:
                            softwareComponents = filter(lambda e: e['displayName'].startswith(libraryToFilterBy), softwareComponents)
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
