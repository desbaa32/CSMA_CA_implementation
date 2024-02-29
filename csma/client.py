import socket
import zlib
import time

from scapy.config import conf
from scapy.layers.dot11 import Dot11FCS, RadioTap, Dot11WEP, Dot11Elt, Dot11, Dot11QoS
from scapy.layers.l2 import LLC, SNAP

# Adresse MAC de la station source
src_mac = "00:11:22:33:44:55"
# Adresse MAC de la station destination
dst_mac = "66:77:88:99:AA:BB"
# Durée de la transmission
duration = 10000
conf.wepkey = ""
nav = 0

def main():
    global nav
    client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client.connect(('127.0.0.1', 12345))
    time.sleep(0.1)
    #while True:
    if nav == 0:
        # Simuler la génération d'une trame RTS
        rts_frame = generate_rts()
        print("[Client] Sending RTS frame...")
        client.sendall(bytes(rts_frame))

        # Attendre la réception de la trame CTS
        print("[Client] Waiting for CTS frame...")
        cts_frame = client.recv(1024)
        print("[Client] Received CTS frame.")
        RadioTap(cts_frame).show()

        # Mettre à jour le NAV
        update_nav(cts_frame)
        # update_nav(Dot11Elt(cts_frame))
        # Simuler la génération d'une trame RTS
        data_frame = generate_data()
        print("[Client] Sending data frame...")
        client.sendall(bytes(data_frame))

        # Attendre la réception de la trame CTS
        print("[Client] Waiting for ACK frame...")
        ack_frame = client.recv(1024)
        print("[Client] Received ACK frame.")
        RadioTap(ack_frame).show()
        print("[End of transmission")
        client.close()
        time.sleep(0.01)
        # Réinitialiser le NAV
        nav = 0
    else:
        #time.sleep(0.1)
        time.sleep(nav)

def calculate_fcs(frame):
    # La fonction scapy utils.crc32 est utilisée pour calculer le FCS
    fcs = zlib.crc32(bytes(frame)) & 0xffffffff
    return fcs

# Fonction pour générer une trame RTS
def generate_rts():
    rts_frame = RadioTap() / Dot11FCS(type=1, subtype=11, FCfield=0x11, addr1=dst_mac, addr2=src_mac)
    rts_frame /= Dot11Elt(ID=8, info=duration.to_bytes(2, byteorder='little'))  # ID 8 pour la durée
    rts_frame.fcs = calculate_fcs(rts_frame)
    return rts_frame

# Fonction pour générer une trame CTS
def generate_cts():
    cts_frame = RadioTap() / Dot11FCS(type=1, subtype=12, FCfield=0x14, addr1=dst_mac)
    cts_frame /= Dot11Elt(ID=8, info=duration.to_bytes(2, byteorder='little'))  # ID 8 pour la durée
    # cts_frame = RadioTap() / Dot11(type=1, subtype=12, addr1=dst_mac, addr2=src_mac)
    cts_frame.fcs = calculate_fcs(cts_frame)
    return cts_frame

# Fonction pour générer une trame ACK
def generate_ack():
    ack_frame = RadioTap() / Dot11FCS(type=1, subtype=13, FCfield=0x15, addr1=dst_mac)
    ack_frame /= Dot11Elt(ID=8, info=duration.to_bytes(2, byteorder='little'))  # ID 8 pour la durée
    # ack_fra
    # me = RadioTap() / Dot11(type=1, subtype=13, addr1=dst_mac, addr2=src_mac)
    ack_frame.fcs = calculate_fcs(ack_frame)
    return ack_frame

# Fonction pour générer une trame de données
def generate_data(payload="Hello, WiFi!"):
    data_frame = RadioTap() / Dot11FCS(type=2, subtype=8, FCfield=0x08, addr1=dst_mac, addr2=src_mac, addr3=dst_mac) / \
                 Dot11QoS() / Dot11WEP() / LLC() / SNAP() / payload
    data_frame /= Dot11Elt(ID=8, info=duration.to_bytes(2, byteorder='little'))  # ID 8 pour la durée
    # data_frame.fcs = calculate_fcs(data_frame)
    return data_frame
#
def update_nav(cts_frame):
    global nav
    # nav = int.from_bytes(cts_frame[Dot11Elt].info, byteorder='little')
    nav=duration+0.01;
# def update_nav(cts_frame):
#     global nav
#     cts_packet = Dot11FCS(cts_frame)
#     nav = int.from_bytes(cts_packet[Dot11Elt].info, byteorder='little')


if __name__ == "__main__":
    main()
