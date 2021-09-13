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
        self.local_host = ""
        self.local_port = 0
        self.servers = None

    def from_dict(self, dic: dict):
        ''' from dict '''
        self.local_host = str(dic.get("local_host", "0.0.0.0"))
        self.local_port = int(dic.get("local_port", 54320))
        self.servers = dic.get("servers", [])
