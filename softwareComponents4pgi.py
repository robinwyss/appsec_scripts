#!/usr/bin/env python
import requests
import csv
import pandas as pd
from io import StringIO
from argparse import ArgumentParser

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-id", "--id", dest="entityId", help="The ID of the Process Group for which libraries should be retrieved", required=True)

args = parser.parse_args()

env = args.environment
apiToken = args.token
entityId = args.entityId

# get a list of all security problems from the specified environment
# makes subsequent calls to the API if the results are paged.  
def getSoftwareComponents(env, apiToken):
    securityProblems = []
    response = queryApi(env, apiToken, '/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi&entitySelector=entityId("'+entityId+'")')
    return response["entities"][0]["toRelationships"]["isSoftwareComponentOfPgi"]

# gets the details for a specific security problem
def getSoftwareComponentDetails(env, apiToken, id):
    return queryApi(env, apiToken, '/api/v2/entities?entitySelector=entityId("'+id+'")')

def queryApi(env, apiToken, endpoint):
    authHeader = {'Authorization' : 'Api-Token '+ apiToken}
    response = requests.get(env + endpoint, headers=authHeader)
    print('.', end="", flush=True) # print a dot for every call to show activity
    return response.json()

def writeResultToFile(filename, result):
    df = pd.json_normalize(result)
    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under softwareComponentDetails.csv')


# retireve all security problems
softwareComponents = getSoftwareComponents(env, apiToken)
softwareComponentDetails = []
for comp in softwareComponents:
        softwareComponentDetail = getSoftwareComponentDetails(env, apiToken, comp["id"])
        softwareComponentDetails.append(softwareComponentDetail)
writeResultToFile('softwareComponentDetails.csv', softwareComponentDetails)