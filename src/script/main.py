''' main '''
from network import p2p

def main():
    with open("../../config/network.json") as f:
        p2p_instance = p2p.P2P(f.read())
        p2p_instance.search_stun()

if __name__ == "__main__":
    main()
