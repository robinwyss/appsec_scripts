import requests
import logging
import time
from functools import lru_cache

timeframe = 'now-1h'

class DynatraceApi:
    def __init__(self, tenant, apiToken, verifySSL = True):
        self.tenant = tenant
        self.apiToken = apiToken
        self.verifySSL = verifySSL

    def queryApi(self, endpoint):
        """
        Calls the given endpoint on the Dynatrace API. 
        param: string endpoint: API endpoint to be called
        return: response as json
        """
        authHeader = {'Authorization' : 'Api-Token '+ self.apiToken}
        #added hard-coded cookies for managed tenant access comment out for SaaS env
        cookies = {'JSESSIONID' : 'node01f3xapxugb6001gantga3g4z0q8174157.node0','b925d32c': 'RRJIKUEGPV7HQSQGP3LFBRU5QQ' }
        url = self.tenant + endpoint
        start_time=time.time()
        response = requests.get(url, headers=authHeader, verify=self.verifySSL, cookies=cookies)
        logging.info(f'API Call Status: {response.status_code} (took {(time.time() - start_time):.2f}s) Request: {url} ');
        logging.debug(f'Response: {response.content}' )
        if response.reason != 'OK':
            logging.error(f'Request {url} failed')
            logging.error(f'Status Code: {response.status_code} ({response.reason}), Response: {response.content}')
            raise RuntimeError(f'API request failed: {response.status_code} ({response.reason})', response.content)
        print('.', end="", flush=True) # print a dot for every call to show activity
        return response.json()
 
    def getSecurityProblems(self):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?pageSize=500')
   
    
    @lru_cache(maxsize=None)
    def getSecurityProblemsByCVE(self, cveID):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?pageSize=500&securityProblemSelector=cveId("'+cveID+'")')
    
    
    @lru_cache(maxsize=None)
    def getSecurityProblemsForSoftwareComponent(self,scID):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?securityProblemSelector=vulnerableComponentIds("'+scID+'")&fields=%2BriskAssessment,%2BmanagementZones&from=-2h')

    
    @lru_cache(maxsize=None)
    def getSecurityProblemsForProcessGroup(self,pgID):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?securityProblemSelector=affectedPgIds("'+pgID+'")&fields=%2BriskAssessment,%2BmanagementZones&from=-2h')

    def __querySecurityProblems(self, endpoint):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        securityProblems = []
        response = self.queryApi(endpoint)
        securityProblems += response["securityProblems"]
        while("nextPageKey" in response):
            response = self.queryApi('/api/v2/securityProblems?nextPageKey='+response["nextPageKey"])
            securityProblems += response["securityProblems"]
        return securityProblems

    
    @lru_cache(maxsize=None)
    def getSecurityProblemDetails(self, securityProblemId):
        """
        gets the details for a specific security problem
        """
        return self.queryApi('/api/v2/securityProblems/'+securityProblemId+'?fields=%2BrelatedEntities,%2BriskAssessment, %2BmanagementZones')

    
    @lru_cache(maxsize=None)
    def getSoftwareComponentsForPGI(self, pgiID):
        """
        Get all Software Components for a given PGI ID
        :param string ID of the Process Group Instance for which the Software Components should be retrieved
        :return list of SoftwareComponents (dictionary)
        """
        response = self.queryApi('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi&entitySelector=entityId("'+pgiID+'")&from='+timeframe)
        return response["entities"][0]["toRelationships"]["isSoftwareComponentOfPgi"]

    def getSoftwareComponentDetails(self, softwareComponents):
        """
        Retrieves the details of the specfied software components
        :param list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        return self.getAllEntitiesByIDs('/api/v2/entities?fields=fromRelationships,properties.packageName,properties.softwareComponentFileName,properties.softwareComponentShortName,properties.softwareComponentType&from='+timeframe, softwareComponents)

    def getProcesses(self, processes):
        """
        Retrieves the details of the specfied processes, with thechnolgy details and the relations to software components
        :param list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        return self.getAllEntitiesByIDs('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties,fromRelationships.isProcessOf,fromRelationships.isInstanceOf&from='+timeframe, processes)

       
        #02/11/23 SRS- added back in getProcessessWithDetails for processes_reporting_libraries.py script
     

    def getProcessesWithDetails(self, processes):
        """
        Retrieves the details of the specfied processes, with technology details and the relations to software components
        :param processes: list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        return self.getAllEntitiesByIDs('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties,fromRelationships.isProcessOf,fromRelationships.isInstanceOf&from='+timeframe, processes)

    #added mz to fields returned SRS
    def getHosts(self):
        """
        Get all hosts with the relationships to processes (PGIs)
        :return list of entities (dictionary)
        """
        return self.getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf,managementZones,properties.memoryTotal,properties.monitoringMode&entitySelector=type("HOST")&from='+timeframe)
    
    
    @lru_cache(maxsize=None)
    def getHostsById(self, entityId):
        """
        Get all hosts with the relationships to processes (PGIs)
        :param str id of the host to be retireved, multiple ids can be specified, separated by ',' 
        :return list of entities (dictionary)
        """
        ids = entityId.split(',')
        entityIds = ', '.join(f'"{i}"' for i in ids)
        return self.getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf&entitySelector=entityId('+entityIds+')&from='+timeframe)

    def getAllEntitiesByIDs(self, endpoint, entityRefs):
        """
        Retrieves all entities by the specified entity references.
        param: string endpoint: the API endpoint to call
        param: list entityRefs: entities to be retrieved
        return: list of entities (dictionary) 
        """
        entities = []
        # split the list into chunks of 100 in order to avoid too large requests (URI too long)
        listOfEntityIds = self.splitIntoChunks(entityRefs, 100)
        for entitieIds in listOfEntityIds:
            ids = self.getIdsFromEntities(entitieIds)
            entities += self.getAllEntities(endpoint + '&entitySelector=entityId('+ids+')')
        return entities

    def getAllEntities(self, endpoint):
        """
        Retrieves all entities by the specified api call (handles paging of results)
        param: str endpoint: the API endpoint to call
        return: list of entities (dictionary) 
        """
        entities = []
        response = self.queryApi(endpoint)
        entities += response["entities"]
        while("nextPageKey" in response):
            response = self.queryApi('/api/v2/entities?nextPageKey='+response["nextPageKey"])
            entities += response["entities"]
        return entities

    
    @lru_cache(maxsize=None)
    def getRestartEvents(self,processId):
        """
        Retireves the latest restart event for a given process
        """
        return self.queryApi('/api/v2/events?from=now-12M&eventSelector=eventType("PROCESS_RESTART")&entitySelector=entityId("'+processId+'")')

    
    @lru_cache(maxsize=None)
    def getProcessV1(self,processId):
        """
        Retireves the latest restart event for a given process
        """
        return self.queryApi('/api/v1/entity/infrastructure/processes/'+processId)

    def getIdsFromEntities(self, entities):
        """
        Combines the IDs of the entities into a string to be used in an API call (e.g. '"ID1","ID2..."')
        param: list of entities
        return string
        """
        return ','.join('"'+i['id']+'"' for i in entities)

    def splitIntoChunks(self, lst, n):
        """Yield successive n-sized chunks from lst."""
        for i in range(0, len(lst), n):
            yield lst[i:i + n]
