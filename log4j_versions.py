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
library = 'org.apache.logging.log4j:log4j-core'

# get all software components (libraries)  
def getSoftwareComponents():
    softwareComponents = []
    response = queryApi( '/api/v2/entities?pageSize=500&entitySelector=type("SOFTWARE_COMPONENT")')
    softwareComponents += response["entities"]
    while("nextPageKey" in response):
        response = queryApi('/api/v2/entities?nextPageKey='+response["nextPageKey"])
        softwareComponents += response["entities"]
    return softwareComponents

# gets the Process Group Instances and Hotst of a given software component
# returns a dictionary mapping hosts to lists of PGIs
def getHostsForComponent(component):
    pgis = getPGIsForComponent(component['entityId'])
    hosts = {};
    for pgi in pgis:
        for host in pgi['fromRelationships']['isProcessOf']:
            hostInfo = getHost(host['id'])
            hostname = hostInfo['displayName']
            if hostname not in hosts:
                hosts[hostname] = []
            hosts[hostname].append(pgi['displayName'])
    return hosts

# get the PGI for a certain Software Component
def getPGIsForComponent(entityId):
    response = queryApi('/api/v2/entities?entitySelector=entityId("'+entityId+'")&fields=fromRelationships')
    pgis = response["entities"][0]['fromRelationships']['isSoftwareComponentOfPgi']
    pgiIds = functools.reduce(lambda a,b: a+'"'+b['id']+'",', pgis, "")[:-1]
    response = queryApi( '/api/v2/entities?entitySelector=entityId('+pgiIds+')&fields=fromRelationships.isProcessOf')
    return response["entities"]

def getHost( hostId):
    response = queryApi( '/api/v2/entities?entitySelector=entityId("'+hostId+'")')
    return response["entities"][0]

def queryApi(endpoint):
    authHeader = {'Authorization' : 'Api-Token '+ apiToken}
    response = requests.get(env + endpoint, headers=authHeader)
    print('.', end="", flush=True) # print a dot for every call to show activity
    return response.json()

def isLog4j(entity):
    return entity['displayName'].startswith(library)

# retireve all security problems
softwareComponents = getSoftwareComponents()
log4jComponents = filter(isLog4j, softwareComponents)

with open('log4j-version-hosts.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    writer.writerow(['log4jversion', 'host', 'process1', 'process2', 'process3', 'process4', 'process5'])

    for comp in log4jComponents:
        hosts = getHostsForComponent(comp)
        for host in hosts:
            cols = [comp['displayName'], host] + hosts[host]
            writer.writerow(cols)