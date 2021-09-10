''' config '''
import json

class NetworkConfig():
    ''' network config '''

    def __init__(self):
        ''' init '''
        self.stun = STUNConfig()

    def from_json(self, data: str):
        ''' from json '''
        self.from_dict(json.loads(data))

    def from_dict(self, dic: dict):
        ''' from dict '''
        self.stun.from_dict(dic.get("stun", {}))

class STUNConfig():
    ''' STUN config '''

    def __init__(self):
        ''' init '''
        self.local_host = None
        self.local_port = None
        self.servers = None

    def from_dict(self, dic: dict):
        ''' from dict '''
        self.local_host = dic.get("local_host", "0.0.0.0")
        self.local_port = dic.get("local_port", 54320)
        self.servers = dic.get("servers", [])
