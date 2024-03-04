#!/usr/bin/env python
import sys
from argparse import ArgumentParser
import csv
from dynatrace_api import DynatraceApi
import logging
import logging.config
import time
import re


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


start_time = time.time()

# get the Dynatrace Environmemnt (URL) and the API Token and default parameters
parser = ArgumentParser()
parser.add_argument("-e", "--env", dest="environment", help="The Dynatrace Environment to query", required=True)
parser.add_argument("-t", "--token", dest="token", help="The Dynatrace API Token to use", required=True)
parser.add_argument("--debug", dest="debug", help="Set log level to debbug", action='store_true')
parser.add_argument("-k", "--insecure", dest="insecure", help="Skip SSL certificate validation", action='store_true')

args = parser.parse_args()

env = args.environment
apiToken = args.token
verifySSL = not args.insecure
debug = args.debug

if debug:
    logging.getLogger().setLevel(logging.DEBUG)

logging.basicConfig(filename='output.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logging.info("=" * 200)
logging.info("Running %s ", re.sub(r"dt0c01\.[\S]+", "dt0c01.XXX", " ".join(sys.argv)))
logging.info("=" * 200)


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


dynatraceApi = DynatraceApi(env, apiToken, verifySSL)

attacks = dynatraceApi.getAttacks()
pgiIds = set([])

with open('attack_details.csv', 'w', newline='') as f:
    writer = csv.writer(f, delimiter=",", quoting=csv.QUOTE_ALL)
    # header
    header = ['ID', 'Timestamp', 'Type', 'State', 'Source IP', 'Process Name', 'Container Name', 'Pod Name',
              'Image Name', 'Workload Name', 'Namespace', 'Container Base Name', 'Container IP',
              'Kubernetes Cluster Name']
    writer.writerow(header)
    for attack in attacks:
        fields = [
            attack['displayId'],
            attack['timestamp'],
            attack['attackType'],
            attack['state'],
            attack['attacker']['sourceIp'],
            attack['affectedEntities']['processGroupInstance']['name']
        ]
        container = dynatraceApi.getContainerGroupForPGI(attack['affectedEntities']['processGroupInstance']['id'])
        if container:
            fields += [
                container['displayName'],
                getProperty(container, 'podName'),
                getProperty(container, 'containerImageName'),
                getProperty(container, 'workloadName'),
                getProperty(container, 'namespaceName'),
                ','.join(getProperty(container, 'containerNames')),
                ','.join(getProperty(container, 'ipAddress'))
            ]
            cluster = dynatraceApi.getClusterForCGI(container['entityId'])
            if cluster:
                fields += [cluster['displayName']]
        writer.writerow(fields)

end_time = time.time()
print('')
print(f'Script completed successfully, took {(end_time - start_time):.2f}s')
