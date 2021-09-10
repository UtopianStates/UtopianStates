''' P2P test '''
from . import p2p

def test_init():
    with open("../../config/network.json", 'r') as f:
        instance = p2p.P2P(f.read())
