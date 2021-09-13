''' P2P '''

from . import (config, stun)


class P2P():
    ''' P2P '''

    def __init__(self, conf: str):
        ''' init '''
        self.config = config.NetworkConfig()
        self.config.from_json(conf)
        self.stun_instance = None
        self.nat_type = stun.NatType.BLOCKED

    def search_stun(self):
        ''' search stun '''
        for server in self.config.stun.servers:
            server_split = str(server).split(":")
            host = server_split[0]
            port = 3478
            if len(server_split) > 1:
                port = int(server_split[1])
            stun_tmp = stun.Stun(self.config.stun.local_host,
                                 self.config.stun.local_port, host, port)
            self.nat_type = stun_tmp.check_nat()
            if self.nat_type == stun.NatType.BLOCKED:
                continue
            self.stun_instance = stun_tmp
            print("nat type:", self.nat_type)
            break

    def collect_info(self):
        ''' collect info '''
        pass
