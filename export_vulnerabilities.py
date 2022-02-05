#!/usr/bin/env python
import pandas as pd
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("-d", "--details", dest="details", help="Fetch the details for each security problem (takes longer)", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
showDetails = args.details
verifySSL = not args.insecure

def writeResultToFile(filename, result):
    df = pd.json_normalize(result)
    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under securityProblemDetails.csv')

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

# retireve all security problems
securityProblems = dynatraceApi.getSecurityProblems()

# if the details flag is set, retrieve the details for every security problem
# write result to a CSV file
if showDetails:
    securityProblemDetails = []
    for secP in securityProblems:
        securityProblemDetail = dynatraceApi.getSecurityProblemDetails(secP["securityProblemId"])
        securityProblemDetails.append(securityProblemDetail)
    writeResultToFile('securityProblemDetails.csv', securityProblemDetails)
else:
    writeResultToFile('securityProblems.csv', securityProblems)
