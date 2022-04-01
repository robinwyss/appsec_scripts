#!/usr/bin/env python
import sys
import csv
from argparse import ArgumentParser
from dynatrace_api import DynatraceApi
import logging
import logging.config
logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# get the Dynatrace Environmemnt (URL) and the API Token with arguments
# with the details parameter, the details for each security problem are fetched
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')

parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
verifySSL = not args.insecure

cve = 'CVE-2022-22965'

debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.info("="*200)
logging.info("Running %s ", " ".join(sys.argv))
logging.info("="*200)

dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

def getTechnologieVersion(process, technolotyType):
    """
    Gets the technology information from a process
    param: dictionary entity: the process entity from which the information should be retrieved
    return string: technology version
    """
    softwareTechnologies = process['properties']['softwareTechnologies']
    for technology in softwareTechnologies:
        if technology['type'] == technolotyType and 'version' in technology:
            return technology['version']

with open('spring4shellreport.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    # header
    header = ['process.name', 'process.id', 'java.version', 'tomcat.version']
    writer.writerow(header)

    # retireve all security problems
    securityProblems = dynatraceApi.getSecurityProblemsByCVE(cve)

    # if the details flag is set, retrieve the details for every security problem
    # write result to a CSV file

    for secP in securityProblems:
        securityProblemDetail = dynatraceApi.getSecurityProblemDetails(secP["securityProblemId"])
        processes = dynatraceApi.getProcesses(securityProblemDetail['affectedEntities'])
        for process in processes:
            javaVersion = getTechnologieVersion(process, 'JAVA')
            tomcatVersion = getTechnologieVersion(process, 'APACHE_TOMCAT')

            writer.writerow([process['displayName'],
                process['entityId'],
                javaVersion,
                tomcatVersion
                ])

