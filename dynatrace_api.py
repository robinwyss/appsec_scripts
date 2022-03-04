import requests
import logging

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
        url = self.tenant + endpoint
        response = requests.get(url, headers=authHeader, verify=self.verifySSL)
        logging.info('API Call Status: %s Request: %s', response.status_code, url);
        logging.debug('Response: %s', response.content)
        if response.reason != 'OK':
            logging.error('Request %s failed', url)
            logging.error('Status Code: %s (%s), Response: %s', response.status_code, response.reason, response.content)
            raise RuntimeError(f'API request failed: {response.status_code} ({response.reason})', response.content)
        print('.', end="", flush=True) # print a dot for every call to show activity
        return response.json()
 
    def getSecurityProblems(self):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?pageSize=500')

    def getSecurityProblemsForSoftwareComponent(self,scID):
        """
        get a list of all security problems from the specified environment
        makes subsequent calls to the API if the results are paged.
        """
        return self.__querySecurityProblems('/api/v2/securityProblems?securityProblemSelector=vulnerableComponentIds("'+scID+'")')

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

    def getSecurityProblemDetails(self, securityProblemId):
        """
        gets the details for a specific security problem
        """
        return self.queryApi('/api/v2/securityProblems/'+securityProblemId+'?fields=%2BrelatedEntities,%2BriskAssessment')

    def getSoftwareComponentsForPGI(self, pgiID):
        """
        Get all Software Components for a given PGI ID
        :param string ID of the Process Group Instance for which the Software Components should be retrieved
        :return list of SoftwareComponents (dictionary)
        """
        response = self.queryApi('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi&entitySelector=entityId("'+pgiID+'")')
        return response["entities"][0]["toRelationships"]["isSoftwareComponentOfPgi"]

    def getSoftwareComponentDetails(self, softwareComponents):
        """
        Retrieves the details of the specfied software components
        :param list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        return self.getAllEntitiesByIDs('/api/v2/entities?fields=fromRelationships,properties.packageName,properties.softwareComponentFileName,properties.softwareComponentShortName,properties.softwareComponentType', softwareComponents)

    def getProcesses(self, processes):
        """
        Retrieves the details of the specfied processes, with thechnolgy details and the relations to software components
        :param list of entity references (dic) (e.g. [{'id': ...}])
        :return list of entities (dictionary)
        """
        return self.getAllEntitiesByIDs('/api/v2/entities?fields=toRelationships.isSoftwareComponentOfPgi,properties.processType,properties.softwareTechnologies', processes)

    def getHosts(self):
        """
        Get all hosts with the relationships to processes (PGIs)
        :return list of entities (dictionary)
        """
        return self.getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf&entitySelector=type("HOST")')
    
    def getHostsById(self, entityId):
        """
        Get all hosts with the relationships to processes (PGIs)
        :param str id of the host to be retireved, multiple ids can be specified, separated by ',' 
        :return list of entities (dictionary)
        """
        ids = entityId.split(',')
        entityIds = ', '.join(f'"{i}"' for i in ids)
        return self.getAllEntities('/api/v2/entities?pageSize=500&fields=+toRelationships.isProcessOf&entitySelector=entityId('+entityIds+')')

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

    