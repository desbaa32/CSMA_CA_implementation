import binascii
import socket
import threading
import time
import zlib

from scapy.compat import raw
from scapy.layers.dot11 import Dot11FCS, RadioTap, Dot11WEP, Dot11Elt, Dot11, Dot11QoS
from scapy.layers.l2 import LLC, SNAP

# Adresse MAC de la station source
src_mac = "00:11:22:33:44:55"
# Adresse MAC de la station destination
dst_mac = "66:77:88:99:AA:BB"
# Durée de la transmission
duration = 10000

clients = {}
nav = {}

def handle_client(client_socket, address):
    global clients, nav
    clients[address] = client_socket
    nav[address] = 0
    print(f"[Server] {address} connected.")

    while True:
        if can_transmit(address):
            # Simulation de la station destination
            print(f"[Server] Station destination listening for RTS from {address}...")
            rts_frame = client_socket.recv(1024)
            print(f"[Server] Received RTS frame from {address}:")
            time.sleep(1)
            RadioTap(rts_frame).show()
            # Display payload content
            # print("[Server] Data Frame Payload:", rts_frame)

            # Simuler la génération d'une trame CTS en réponse
            cts_frame = generate_cts()
            print(f"[Server] Sending CTS frame to {address}...")
            client_socket.sendall(bytes(cts_frame))

            # Mettre à jour le NAV des autres clients
            update_nav(address, duration)

            # Attendez un moment pour simuler le traitement de la transmission
            time.sleep(1)

            # Reception d'une trame de données en réponse

            # TODO: Implement data processing logic here
            data_frame_bytes, addr = client_socket.recvfrom(1024)
            print(f"[Server] Received data frame from {address}")
            time.sleep(1)
            data_frame = RadioTap(data_frame_bytes)
            # Dot11WEP(data_frame_bytes).show()
            # LLC(data_frame_bytes).show()
            # SNAP(data_frame_bytes).show()
            # Display payload content
            data_frame.show()
            # Décoder la charge utile de la trame de données
            payload = binascii.hexlify(data_frame_bytes[40:])

            # Afficher le message
            print(f"[Server] Message de la trame de données de {address}:", payload.decode())
            ack_frame = generate_ack()
            print(f"[Server] Sending ACK frame to {address}...")
            client_socket.sendall(bytes(ack_frame))
            client_socket.close()


            # Réinitialiser le NAV de l'expéditeur
            nav[address] = 0
        else:
            time.sleep(0.1)

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

def update_nav(sender, nav_duration):
    global nav
    for client, n in nav.items():
        if client != sender:
            nav[client] = max(n, nav_duration)

def can_transmit(address):
    global nav
    return nav[address] == 0

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('127.0.0.1', 12345))
    server.listen(5)
    print("[Server] Server listening on port 12345")

    while True:
        client_socket, address = server.accept()
        client_handler = threading.Thread(target=handle_client, args=(client_socket, address))
        client_handler.start()

if __name__ == "__main__":
    main()
