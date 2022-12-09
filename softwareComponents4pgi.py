#!/usr/bin/env python
import sys
import pandas as pd
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environment (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

parser.add_argument("-i", "--id", dest="pgiID", help="The ID of the Process Group Instance for which libraries should be retrieved", required=True)

args = parser.parse_args()

env = args.environment
apiToken = args.token
pgiID = args.pgiID
verifySSL = not args.insecure

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

def writeResultToFile(filename, result):
    df = pd.json_normalize(result)
    df.to_csv(filename,sep=';', index=False, quotechar="'", encoding='utf-8')
    print()
    print('results stored under softwareComponentDetails.csv')


# retireve all security problems
softwareComponents = dynatraceApi.getSoftwareComponentsForPGI(pgiID)
softwareComponentDetails = dynatraceApi.getSoftwareComponentDetails(softwareComponents)
writeResultToFile('softwareComponentDetails.csv', softwareComponentDetails)