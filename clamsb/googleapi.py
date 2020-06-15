# Copyright (C) 2019-2020  Cisco Systems, Inc. and/or its affiliates. All rights reserved.
from base64 import b64encode
try:
    from googleapiclient.discovery import build
    from googleapiclient.errors import HttpError
except ImportError:
    from apiclient.discovery import build
    from apiclient.errors import HttpError

class GoogleAPI(object):
    CLIENTID  = "api"
    CLIENTVER = "1.0"

    def __init__(self, apikey):
        self._service = build('safebrowsing', 'v4', developerKey=apikey, cache_discovery=False)

    def get_threats_update(self, client_state):
        request_body = {
            'client': {
                'clientId': self.CLIENTID,
                'clientVersion': self.CLIENTVER,
            },
            'listUpdateRequests': [],
        }

        for item in client_state:
            request_body['listUpdateRequests'].append(
                {
                    'threatType': item.threatType,
                    'platformType': item.platformType,
                    'threatEntryType': item.threatEntryType,
                    'state': item.state,
                    'constraints': {
                        'supportedCompressions': ["RAW"]
                    }
                }
            )
        response = self._service.threatListUpdates().fetch(body=request_body).execute()

        # this is for fair use, we aren't supposed to make a request until this times out
        #self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['listUpdateResponses']

    def get_full_hashes(self, client_state, prefixes):
        request_body = {
            "client": {
                "clientId": self.CLIENTID,
                "clientVersion": self.CLIENTVER,
            },
            "clientStates": [],
            "threatInfo": {
                "threatTypes": [],
                "platformTypes": [],
                "threatEntryTypes": [],
                "threatEntries": [],
            }
        }
        for prefix in prefixes:
            request_body['threatInfo']['threatEntries'].append({"hash": b64encode(prefix).decode()})
        for item in client_state:
            if item.state and item.state not in request_body['clientStates']:
                request_body['clientStates'].append(item.state)
            if item.threatType not in request_body['threatInfo']['threatTypes']:
                request_body['threatInfo']['threatTypes'].append(item.threatType)
            if item.platformType not in request_body['threatInfo']['platformTypes']:
                request_body['threatInfo']['platformTypes'].append(item.platformType)
            if item.threatEntryType not in request_body['threatInfo']['threatEntryTypes']:
                request_body['threatInfo']['threatEntryTypes'].append(item.threatEntryType)
        response = self._service.fullHashes().find(body=request_body).execute()
        # this is for fair use, we aren't supposed to make a request until this times out
        #self.set_wait_duration(response.get('minimumWaitDuration'))
        return response['matches'] if 'matches' in response.keys() else []
