''' P2P '''

from . import (config, stun)


class P2P():
    ''' P2P '''

    def __init__(self, conf: str):
        ''' init '''
        self.config = config.NetworkConfig()
        self.config.from_json(conf)
        self.stun_instance = None

    def search_stun(self):
        ''' search stun '''
        for server in self.config.stun.servers:
            server_split = str(server).split(":")
            host = server_split[0]
            port = 3478
            if len(server_split) > 1:
                port = server_split[1]
            stun_tmp = stun.STUN(self.config.stun.local_host,
                                 self.config.stun.local_port, host, port)
            nat_type = stun_tmp.check_nat()
            if nat_type is None:
                continue
            self.stun_instance = stun_tmp
            print("nat type:", nat_type)

    def collect_info(self):
        ''' collect info '''
        pass
