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
parser.add_argument("-d", "--details", dest="details", help="Fetch the details for each security problem (takes longer)", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
showDetails = args.details

# get a list of all security problems from the specified environment
# makes subsequent calls to the API if the results are paged.  
def getSecurityProblems(env, apiToken):
    securityProblems = []
    response = queryApi(env, apiToken, '/api/v2/securityProblems?pageSize=500')
    securityProblems += response["securityProblems"]
    while("nextPageKey" in response):
        response = queryApi(env, apiToken, '/api/v2/securityProblems?nextPageKey='+response["nextPageKey"])
        securityProblems += response["securityProblems"]
    return securityProblems

# gets the details for a specific security problem
def getSecurityProblemDetails(env, apiToken, securityProblemId):
    return queryApi(env, apiToken, '/api/v2/securityProblems/'+securityProblemId+'?fields=%2BrelatedEntities,%2BriskAssessment')

def queryApi(env, apiToken, endpoint):
    authHeader = {'Authorization' : 'Api-Token '+ apiToken}
    response = requests.get(env + endpoint, headers=authHeader)
    print('.', end="", flush=True) # print a dot for every call to show activity
    return response.json()

def writeResultToFile(filename, result):
    df = pd.json_normalize(result)
    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under securityProblemDetails.csv')


# retireve all security problems
securityProblems = getSecurityProblems(env, apiToken)

# if the details flag is set, retrieve the details for every security problem
# write result to a CSV file
if showDetails:
    securityProblemDetails = []
    for secP in securityProblems:
        securityProblemDetail = getSecurityProblemDetails(env, apiToken, secP["securityProblemId"])
        securityProblemDetails.append(securityProblemDetail)
    writeResultToFile('securityProblemDetails.csv', securityProblemDetails)
else:
    writeResultToFile('securityProblems.csv', securityProblems)
