#!/usr/bin/env python
import sys
import pandas as pd
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi
import csv
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

parser.add_argument("-n", "--name", dest="sc_name",
                    help="The name of the Software Component to query (matching with startsWith)", required=True)

args = parser.parse_args()

env = args.environment
apiToken = args.token
sc_name = args.sc_name
verifySSL = not args.insecure

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("=" * 200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("=" * 200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

with open(sc_name + '-usage.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_ALL)
    # header
    writer.writerow(['sc.name', 'sc.id', 'groupid', 'artifactId', 'version', 'process.name', 'process.id', 'host.id'])
    softwareComponents = dynatraceApi.getSoftwareComponentsByName(sc_name)
    for softwareComponent in softwareComponents:
        scnameparts = softwareComponent['displayName'].split(':')
        groupid = scnameparts[0]
        artifactid = scnameparts[1]
        version = scnameparts[1]
        pgiRefs = softwareComponent['fromRelationships']['isSoftwareComponentOfPgi']
        pgis = dynatraceApi.getProcessesWithDetails(pgiRefs)
        for pgi in pgis:
            writer.writerow(
                [softwareComponent['displayName'], softwareComponent['entityId'], groupid, artifactid, version,
                 pgi['displayName'], pgi['entityId'], pgi['fromRelationships']['isProcessOf'][0]['id']])
