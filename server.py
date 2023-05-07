#!/usr/bin/env python3
import sys
from enum import Enum
import socket
import argparse
import threading
import struct
import random
import select
import datetime

debug = False
server_config_filename = 'server.cfg'
equips_filename = 'equips.dat'

client_list = list()

UDP_PACKAGE_SIZE = 78
TCP_PACKAGE_SIZE = 178

# ----------------------------------
# B -> (unsigned char), [Type]
# 7s -> (string de longitud 7), [id] [random_num]
# 13s -> (string de longitud 13), [MAC_addr]
# 50s -> (string de longitud 50), [Data]
# 150s -> (string de longitud 150) [Data]
UDP_DATA_FORMAT = "B7s13s7s50s"
TCP_DATA_FORMAT = "B7s13s7s150s"
# ----------------------------------

pdu_udp_recv = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}
pdu_udp_send = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}

pdu_tcp_recv = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}
pdu_tcp_send = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}

exit_flag = False  # Ens diu quan hem de tancar el servidor


class RegisterStatus(Enum):
    REGISTER_REQ = 0x00  # Petició de registre
    REGISTER_ACK = 0x02  # Acceptació de registre
    REGISTER_NACK = 0x04  # Deneagació de registre
    REGISTER_REJ = 0x06  # Rebuig de registre
    ERROR = 0x0F  # Error del protocol


class ClientStatus(Enum):
    DISCONNECTED = 0xA0  # Equip desconectat
    WAIT_REG_RESPONSE = 0xA2  # Espera de resposta a la petició de registre
    WAIT_DB_CHECK = 0xA4  # Espera de consulta BB. DD. d’equips autoritzats
    REGISTERED = 0xA6  # Equip registrat, sense intercanvi ALIVE
    SEND_ALIVE = 0xA8  # Equip enviant i rebent paquets d'ALIVE


class AliveStatus(Enum):
    ALIVE_INF = 0x10  # Enviament d'informació d'alive
    ALIVE_ACK = 0x12  # Confirmació de recepció d'informació d'alive
    ALIVE_NACK = 0x14  # Denegacio de recepció d'informació d'alive
    ALIVE_REJ = 0x16  # Rebuig de recepció d'informació d'alive


class SendFileStatus(Enum):
    SEND_FILE = 0x20
    SEND_DATA = 0x22
    SEND_ACK = 0x24
    SEND_NACK = 0x26
    SEND_REJ = 0x28
    SEND_END = 0x2A


class ReceiveFileStatus(Enum):
    GET_FILE = 0x30
    GET_DATA = 0x32
    GET_ACK = 0x34
    GET_NACK = 0x36
    GET_REJ = 0x38
    GET_END = 0x3A


class AliveConstants:
    r = 2
    j = 2
    s = 3


class SendConstants:
    w = 3


def debug_log(message):
    if debug:
        timestamp = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
        print(f"[DEBUG {timestamp}] {message}")


def system_log(message):
    timestamp = datetime.datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    print(f"[SYSTEM {timestamp}] {message}")


def process_command_line_args():
    parser = argparse.ArgumentParser(description="Procesa els arguments passats per la linia de commandes")

    parser.add_argument('-d', '--debug', action='store_true', help="Habilita el mode debug")
    parser.add_argument('-c', '--config', type=str, help="El path al arxiu de configuració del software")
    parser.add_argument('-u', '--equips', type=str, help="Arxiu d'equips autoritzats")

    args = parser.parse_args()
    return args


class ServerConfig:
    def __init__(self, id, mac_addr, udp_port, tcp_port):
        self.id = id
        self.mac_addr = mac_addr
        self.udp_port = int(udp_port)
        self.tcp_port = int(tcp_port)

    def __str__(self):
        return f"Id = {self.id}, MAC = {self.mac_addr}, UDP-port = {self.udp_port}, TCP-port = {self.tcp_port}"


class Client:
    def __init__(self, id, mac_addr, status="DISCONNECTED", random="000000"):
        self.id = id
        self.mac_addr = mac_addr
        self.status = status
        self.random_num = random
        self.num_paquets = 0
        self.ip = ""
        self.time_UDP = datetime.datetime.now()
        self.time_TCP = datetime.datetime.now()
        self.isTransferingTCPdata = False
        self.TCPfd = 0

    def reset(self):
        self.random_num = "000000"
        self.num_paquets = 0
        self.ip = ""
        self.time_UDP = datetime.datetime.now()
        self.time_TCP = datetime.datetime.now()
        self.isTransferingTCPdata = False
        self.TCPfd = 0


# Ens guardem les parelles d'identificador i MAC en un diccionari
def read_equips_file(file_path):
    equips = {}
    with open(file_path, 'r') as f:
        for line in f:
            id, mac_address = line.strip().split(' ')
            equips[id] = mac_address
            client_list.append(Client(id, mac_address))  # Creem i guardem els objectes client que estiguin autoritzats
    f.close()
    return equips


def get_client(id):
    for client in client_list:
        if client.id == id:
            return client
    return None


def read_server_config(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()

    lines = [line.strip() for line in lines]  # Eliminem els newline chars

    config_dict = {}

    # guardem els valors llegits en un diccionari per poder retornar l'objecte
    for line in lines:
        key, value = line.split()
        config_dict[key.strip()] = value.strip()

    return ServerConfig(config_dict['Id'], config_dict['MAC'], config_dict['UDP-port'], config_dict['TCP-port'])


# Elimina els caracters null i el "b'" que denota el bytes-like type
def extract_hex_string(s):
    hex_str = s.split("\\x00")[0]
    hex_str = hex_str.replace("b'", '')

    return hex_str


def unpacked_data_to_PDU(unpacked_data):
    result = {}

    result["type"] = extract_hex_string(hex(int(unpacked_data[0])))
    result["id"] = extract_hex_string(str(unpacked_data[1]))
    result["MAC_addr"] = extract_hex_string(str(unpacked_data[2]))
    result["random_num"] = extract_hex_string(str(unpacked_data[3]))
    result["data"] = extract_hex_string(str(unpacked_data[4]))

    return result


# S'encarrega d'enviar paquets i omplir els camps corresponents segons els casos especifics
def send_UDP_packet(packet_type, id, addr, data=""):
    client = get_client(id)
    global pdu_udp_send
    # pdu_udp_send = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}
    pdu_udp_send["id"] = server_config.id + "\0"
    pdu_udp_send["MAC_addr"] = server_config.mac_addr + "\0"
    if client is not None:
        pdu_udp_send["random_num"] = client.random_num + "\0"
    pdu_udp_send["data"] = "\0"

    if packet_type == RegisterStatus.REGISTER_ACK.value:
        if not (client.status == "REGISTERED" or client.status == "ALIVE"):
            client.status = "REGISTERED"
            system_log(f"El client passa al estat {client.status}")

            client.ip = addr[0]
            debug_log(f"Client: {id}, IP: {client.ip}")

            rand = str(random.randint(100000, 999999))
            pdu_udp_send["random_num"] = rand + "\0"
            client.random_num = rand

            pdu_udp_send["data"] = str(server_config.tcp_port) + "\0"

            client.time_UDP = datetime.datetime.now()  # Emmagatzemem en quin instant de temps hem iniciat el registre

    # Si no està autoritzat s’enviarà un paquet [REGISTER_REJ]
    # amb tots els camps de la PDU a valor zeros i en el camp [data] el motiu del rebuig.
    if packet_type == RegisterStatus.REGISTER_REJ.value or packet_type == RegisterStatus.REGISTER_NACK.value:
        pdu_udp_send["MAC_addr"] = "000000000000\0"
        pdu_udp_send["random_num"] = "000000\0"
        pdu_udp_send["data"] = data  # Motiu del rebuig passat com a parametre

    # ----- Control Alives -------
    if packet_type == AliveStatus.ALIVE_ACK.value:

        client.time_UDP = datetime.datetime.now()  # Emmagatzemem en quin instant de temps hem rebut l'últim alive correcte

        if client.status == "REGISTERED":
            client.status = "ALIVE"
            system_log(f"El client passa al estat {client.status}")

    if packet_type == AliveStatus.ALIVE_REJ.value or packet_type == AliveStatus.ALIVE_NACK.value:
        pdu_udp_send["MAC_addr"] = "000000000000\0"
        pdu_udp_send["random_num"] = "000000\0"
        pdu_udp_send["data"] = data  # Motiu del rebuig passat com a parametre

    # Crear la trama a partir de la PDU guardada en forma de diccionari
    packet_to_send = struct.pack(UDP_DATA_FORMAT, packet_type,
                                 pdu_udp_send["id"].encode(), pdu_udp_send["MAC_addr"].encode(),
                                 pdu_udp_send["random_num"].encode(), pdu_udp_send["data"].encode())

    # Incrementem el nombre de paquets que hem enviat al client
    if client is not None:
        client.num_paquets += 1

    # Enviar la trama
    num_bytes = udp_sock.sendto(packet_to_send, addr)
    # debug_string = f"Enviat={num_bytes} " + str(pdu_udp_send)
    debug_string = f"Enviat={num_bytes} " + str(unpacked_data_to_PDU(struct.unpack(UDP_DATA_FORMAT, packet_to_send)))
    debug_log(debug_string)


def send_TCP_packet(packet_type, id, sock, data=""):
    client = get_client(id)
    global pdu_tcp_send

    # pdu_tcp_send = {"type": 0x00, "id": "", "MAC_addr": "", "random_num": "", "data": ""}

    pdu_tcp_send["id"] = server_config.id + "\0"
    pdu_tcp_send["MAC_addr"] = server_config.mac_addr + "\0"
    if client is not None:
        pdu_tcp_send["random_num"] = client.random_num + "\0"
    pdu_tcp_send["data"] = "\0"

    if packet_type == SendFileStatus.SEND_REJ.value or packet_type == SendFileStatus.SEND_NACK.value:
        pdu_tcp_send["MAC_addr"] = "000000000000\0"
        pdu_tcp_send["random_num"] = "000000\0"
        pdu_tcp_send["data"] = data
        pdu_tcp_send["id"] = "\0"

    if packet_type == SendFileStatus.SEND_ACK.value:
        nom_arxiu_conf = id + ".cfg"
        pdu_tcp_send["data"] = nom_arxiu_conf

        client.time_TCP = datetime.datetime.now()
        client.isTransferingTCPdata = True

    if packet_type == ReceiveFileStatus.GET_REJ.value or packet_type == ReceiveFileStatus.GET_NACK.value:
        pdu_tcp_send["MAC_addr"] = "000000000000\0"
        pdu_tcp_send["random_num"] = "000000\0"
        pdu_tcp_send["data"] = data
        pdu_tcp_send["id"] = "\0"

    if packet_type == ReceiveFileStatus.GET_ACK.value:
        nom_arxiu_conf = id + ".cfg"
        pdu_tcp_send["data"] = nom_arxiu_conf

        client.time_TCP = datetime.datetime.now()
        client.isTransferingTCPdata = True

    if packet_type == ReceiveFileStatus.GET_DATA.value:
        pdu_tcp_send["data"] = data

    packet_to_send = struct.pack(TCP_DATA_FORMAT, packet_type,
                                 pdu_tcp_send["id"].encode(), pdu_tcp_send["MAC_addr"].encode(),
                                 pdu_tcp_send["random_num"].encode(), pdu_tcp_send["data"].encode())

    num_bytes = sock.send(packet_to_send)
    # debug_string = f"Enviat={num_bytes} " + str(pdu_tcp_send)
    debug_string = f"Enviat={num_bytes} " + str(unpacked_data_to_PDU(struct.unpack(TCP_DATA_FORMAT, packet_to_send)))
    debug_log(debug_string)


def is_authorized(id, mac_addr):
    return id in equips_dictionary and equips_dictionary[id] == mac_addr


def is_REGISTERED_or_ALIVE(client):
    return client.status == "REGISTERED" or client.status == "ALIVE"


# Per a atendre peticions de registre
def handle_REGISTER_REQ(pdu_udp, addr):
    client = get_client(pdu_udp["id"])
    id = pdu_udp["id"]
    mac_addr = pdu_udp["MAC_addr"]
    random_num = pdu_udp["random_num"]

    # Mirar si l'equip està autoritzat per emprar el sistema
    if is_authorized(id, mac_addr):
        # Si hi ha discrepancies amb el numero aleatori
        if check_discrepancy(client, random_num, addr) == -1:
            send_UDP_packet(RegisterStatus.REGISTER_NACK.value, id, addr, "Discrepancies amb el numero aleatori")

        # Si hi ha discrepancies amb l'adreça IP de l'equip
        elif check_discrepancy(client, random_num, addr) == -2:
            debug_log("Discrepàncies amb la ip del dispositiu: " + str(id))
            send_UDP_packet(RegisterStatus.REGISTER_NACK.value, id, addr, "Discrepancies amb la ip")

        else:
            debug_log("Equip autoritzat: " + str(id))
            # En cas afirmatiu s'envia REG_ACK
            send_UDP_packet(RegisterStatus.REGISTER_ACK.value, id, addr)

    else:
        debug_log("Equip no autoritzat: " + str(id))
        # Si no esta autoritzat s'envia REG_REJ
        send_UDP_packet(RegisterStatus.REGISTER_REJ.value, id, addr, "L'equip no està autoritzat en el sistema")


# Comprova discrepàncies en el nombre aleatori o en l'adreça
# - Si retorna 0 -> el paquet és correcte
# - Si retorna -1 -> hi ha discrepancia amb el nombre aleatori.
# - Si retorna -2 -> hi ha discrepancia amb la ip del dispositu.
def check_discrepancy(client, random_num, addr):
    # Si hi ha discrepancies amb el numero aleatori
    if random_num != client.random_num:
        debug_log("Discrepàncies amb el numero aleatori al dispositiu: " + str(client.id))
        return -1

    # Si hi ha discrepancies amb l'adreça IP de l'equip
    if client.num_paquets > 0 and addr[0] != client.ip:
        debug_log("Discrepàncies amb la ip del dispositiu: " + str(client.id))
        return -2

    return 0


def handle_ALIVE_INF(pdu_udp, addr):
    client = get_client(pdu_udp["id"])
    id = pdu_udp["id"]
    mac_addr = pdu_udp["MAC_addr"]
    random_num = pdu_udp["random_num"]

    if is_authorized(id, mac_addr):

        if not is_REGISTERED_or_ALIVE(client):
            send_UDP_packet(AliveStatus.ALIVE_REJ.value, id, addr, "L'equip no està registrat en el sistema")

        if check_discrepancy(client, random_num, addr) == -1:
            send_UDP_packet(AliveStatus.ALIVE_NACK.value, id, addr, "Discrepàncies amb el numero aleatori")

        elif check_discrepancy(client, random_num, addr) == -2:
            send_UDP_packet(AliveStatus.ALIVE_NACK.value, id, addr, "Discrepàncies amb la ip")

        else:
            send_UDP_packet(AliveStatus.ALIVE_ACK.value, id, addr)
    else:
        send_UDP_packet(AliveStatus.ALIVE_REJ.value, id, addr, "Equip no autoritzat o no registrat")


def handle_SEND_FILE(pdu_udp, sock, addr):
    client = get_client(pdu_udp["id"])
    id = pdu_udp["id"]
    mac_addr = pdu_udp["MAC_addr"]
    random_num = pdu_udp["random_num"]

    if is_authorized(id, mac_addr) and (client.status == "ALIVE" or client.status == "REGISTERED"):

        if check_discrepancy(client, random_num, addr) == -1:
            send_TCP_packet(SendFileStatus.SEND_NACK.value, id, sock, "Discrepancia en el numero aleatori")
        elif check_discrepancy(client, random_num, addr) == -2:
            send_TCP_packet(SendFileStatus.SEND_NACK.value, id, sock, "Discrepancia amb la ip")
        elif client.isTransferingTCPdata:
            send_TCP_packet(SendFileStatus.SEND_NACK.value, id, sock,
                            "El client ja esta efectuant una operació amb el seu arxiu de configuració")
        else:
            nom_arxiu_conf = id + ".cfg"

            send_TCP_packet(SendFileStatus.SEND_ACK.value, id, sock, nom_arxiu_conf)
            system_log("Acceptada petició d'enviament d'arxiu de configuració")

            return open(nom_arxiu_conf, "w")
    else:
        if client is not None:
            send_TCP_packet(SendFileStatus.SEND_REJ.value, id, sock,
                            "Discrepància amb les dades principals del equip (equip no autoritzat o no registrat")
        else:
            debug_log("Ha arribat un paquet amb un id invàlid")


def handle_GET_CONF(pdu_udp, sock, addr):
    client = get_client(pdu_udp["id"])
    id = pdu_udp["id"]
    mac_addr = pdu_udp["MAC_addr"]
    random_num = pdu_udp["random_num"]

    if is_authorized(id, mac_addr) and (client.status == "ALIVE" or client.status == "REGISTERED"):

        if check_discrepancy(client, random_num, addr) == -1:
            send_TCP_packet(ReceiveFileStatus.GET_NACK.value, id, sock, "Discrepancia en el numero aleatori")
        elif check_discrepancy(client, random_num, addr) == -2:
            send_TCP_packet(ReceiveFileStatus.GET_NACK.value, id, sock, "Discrepancia amb la ip")
        elif client.isTransferingTCPdata:
            send_TCP_packet(ReceiveFileStatus.GET_NACK.value, id, sock,
                            "El client ja esta efectuant una operació amb el seu arxiu de configuració")
        else:
            nom_arxiu_conf = id + ".cfg"

            send_TCP_packet(ReceiveFileStatus.GET_ACK.value, id, sock, nom_arxiu_conf)
            system_log("Acceptada petició d'obetnció d'arxiu de configuració")

            client.isTransferingTCPdata = True

            for line in read_config_data(nom_arxiu_conf):
                send_TCP_packet(ReceiveFileStatus.GET_DATA.value, id, sock, line + "\n")

            send_TCP_packet(ReceiveFileStatus.GET_END.value, id, sock)

            client.isTransferingTCPdata = False

            debug_log("Tancant socket TCP")
            sock.close()
    else:
        if client is not None:
            send_TCP_packet(ReceiveFileStatus.GET_REJ.value, id, sock,
                            "Discrepància amb les dades principals del equip (equip no autoritzat o no registrat")
        else:
            debug_log("Ha arribat un paquet amb un id invàlid")


# Processa la PDU rebuda
def process_PDU_UDP_data(pdu_udp, addr):
    packet_type = int(pdu_udp["type"], 16)
    id = pdu_udp["id"]
    client = get_client(id)

    # Atendre peticions de registre
    if packet_type == RegisterStatus.REGISTER_REQ.value:
        client.status = "WAIT_DB_CHECK"
        system_log(f"El client passa al estat {client.status}")
        handle_REGISTER_REQ(pdu_udp, addr)

    # Control de manteniment de comunicació
    if packet_type == AliveStatus.ALIVE_INF.value:
        handle_ALIVE_INF(pdu_udp, addr)


def write_config_data(data):
    if not file.closed:
        file.write(data.encode().decode('unicode_escape'))


def read_config_data(file_path):
    with open(file_path, 'r') as f:
        data = [line.strip() for line in f.readlines()]

    f.close()
    return data


file = None


def process_PDU_TCP_DATA(pdu_udp, sock, addr):
    packet_type = int(pdu_udp["type"], 16)
    id = pdu_udp["id"]
    client = get_client(id)

    if client is not None:
        client.TCPfd = sock

    global file

    if packet_type != SendFileStatus.SEND_END.value and packet_type != ReceiveFileStatus.GET_FILE.value:
        # --- Enviament de configuració ---
        if packet_type == SendFileStatus.SEND_FILE.value:
            file = handle_SEND_FILE(pdu_udp, sock, addr)

        elif packet_type == SendFileStatus.SEND_DATA.value:
            client.time_TCP = datetime.datetime.now()
            write_config_data(pdu_udp["data"])

        else:
            debug_log("s'ha rebut un paquet inesperat abans del SEND_END")

        handle_client_tcp(sock, addr)

    elif packet_type == ReceiveFileStatus.GET_FILE.value:
        # --- Recepció de configuració ---
        handle_GET_CONF(pdu_udp, sock, addr)

    else:
        system_log("Finalitzat l'enviament o obtenció del arxiu")
        client.isTransferingTCPdata = False
        file.close()
        debug_log("Tancant socket TCP")
        sock.close()


def handle_client_udp(data, sock):
    global pdu_udp_recv

    # Desempaquetem les dades rebudes amb struct.unpack
    unpacked_data = struct.unpack(UDP_DATA_FORMAT, data)

    # Guardem i decodifiquem les dades rebudes en un diccionari
    pdu_udp_recv = unpacked_data_to_PDU(unpacked_data)
    debug_log("Rebut: " + str(pdu_udp_recv))

    # Tractem les dades
    process_PDU_UDP_data(pdu_udp_recv, sock)


def handle_client_tcp(sock, addr):
    data = sock.recv(TCP_PACKAGE_SIZE)

    global pdu_tcp_recv

    try:
        # Desempaquetem les dades rebudes amb struct.unpack
        unpacked_data = struct.unpack(TCP_DATA_FORMAT, data)

        # Guardem i decodifiquem les dades rebudes en un diccionari
        pdu_tcp_recv = unpacked_data_to_PDU(unpacked_data)
        debug_log("Rebut: " + str(pdu_tcp_recv))

        # Tractem les dades
        process_PDU_TCP_DATA(pdu_tcp_recv, sock, addr)

    except struct.error as e:
        debug_log("Tancant socket TCP")
        sock.close()


def check_timers():
    for client in client_list:
        current_time = datetime.datetime.now()
        time_diff_udp = (current_time - client.time_UDP).total_seconds()

        time_diff_tcp = (current_time - client.time_TCP).total_seconds()

        # r = 2, j = 2, s = 3

        intervals_enviament = time_diff_udp // AliveConstants.r

        # Temporització del primer alive
        if (client.status == "REGISTERED" or client.status == "WAIT_DB_CHECK") and intervals_enviament > AliveConstants.j:
            debug_log(
                f"No s'ha rebut un paquet ALIVE_INF abans de {AliveConstants.j} intervals d'enviament ({AliveConstants.r}) del client {client.id}, passa al estat DISCONNECTED")
            client.status = "DISCONNECTED"

        # Perdua d'ALIVES
        if client.status == "ALIVE" and intervals_enviament > AliveConstants.s:
            debug_log(
                f"S'han deixat de rebre {AliveConstants.s} Alives consecutius del client {client.id}, passa al estat DISCONNECTED")
            client.status = "DISCONNECTED"

        # Recepció de paquets TCP
        if time_diff_tcp > SendConstants.w and client.isTransferingTCPdata:
            debug_log(f"L'interval de recepció de paquets es superior a {SendConstants.w}, tancant canal TCP")
            client.isTransferingTCPdata = False
            client.TCPfd.close()

        if client.status == "DISCONNECTED":
            client.reset()  # Reiniciem a tots els valors per defecte


def print_table(data):
    headers = ("--ID--", "------IP-------", "-----MAC----", "---ALEA---", "----ESTAT---")
    col_widths = [len(header) for header in headers]
    for row in data:
        for i in range(len(headers)):
            col_widths[i] = max(col_widths[i], len(str(row[i])))

    header_str = "|".join(["{:^{}}".format(header, col_widths[i]) for i, header in enumerate(headers)])
    print("-" * len(header_str))
    print(header_str)

    for row in data:
        row_str = "|".join(["{:<{}}".format(str(row[i]), col_widths[i]) for i in range(len(headers))])
        print(row_str)

    print("-" * len(header_str))


def treat_command(command):
    if command == "list":
        data = []
        for client in client_list:
            data.append([client.id, client.ip, client.mac_addr, client.random_num, client.status])
        print_table(data)

    elif command == "quit":
        global udp_sock, tcp_sock, exit_flag

        exit_flag = True

        tcp_sock.close()
        tcp_sock.close()

        debug_log("Tancant el servidor...")

    else:
        system_log(f"La comanda {command} és invàlida")


def wait_for_connections():
    global udp_sock, tcp_sock

    sockets_list = [udp_sock, tcp_sock, sys.stdin]

    while not exit_flag:

        # Ens assegurem que les temporitzacions es compleixin
        check_timers()

        # use select to wait for incoming packets
        read_sockets, _, _ = select.select(sockets_list, [], [], 0)

        for sock in read_sockets:
            # Si ho rebem per UDP
            if sock == udp_sock:
                # detect the first connection from a client
                data, addr = udp_sock.recvfrom(UDP_PACKAGE_SIZE)

                # create a new thread to handle the connection
                t = threading.Thread(target=handle_client_udp, args=(data, addr))
                debug_log("Fil creat per atendre paquet UDP de: " + str(addr))
                t.start()

            # Si ho rebem per TCP
            if sock == tcp_sock:
                # detect the first conneection from a client
                client_socket, client_adress = tcp_sock.accept()

                t = threading.Thread(target=handle_client_tcp, args=(client_socket, client_adress))
                debug_log("Fil creat per atendre paquet TCP de: " + str(client_adress))
                t.start()

            # Si escribim per stdin
            if sock == sys.stdin:
                command = sys.stdin.readline().strip()  # Llegim la commanda per consola
                treat_command(command)


def initialize_sockets():
    global udp_sock, tcp_sock

    # Crear socket UDP i fer bind
    udp_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        udp_sock.bind(('localhost', server_config.udp_port))
        udp_sock.setblocking(False)
    except socket.error as err:
        print(f"El bind UDP ha fallat: {err}")

    debug_log(f"Socket UDP creat i bind fet al port: {server_config.udp_port}")

    # Crear socket TCP i fer bind
    tcp_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        tcp_sock.bind(('localhost', server_config.tcp_port))
        # Listen for incoming connections
        tcp_sock.listen(5)
        tcp_sock.setblocking(False)
    except socket.error as err:
        print(f"El bind TCP ha fallat: {err}")

    debug_log(f"Socket TCP creat i bind fet al port: {server_config.tcp_port}")


def main():

    try:
        global debug, server_config_filename, equips_filename, server_config, equips_dictionary
        args = process_command_line_args()

        if args.debug:
            debug = True
            debug_log("Mode debug activat!")

        if args.config:
            server_config = args.config

        if args.equips:
            equips_filename = args.equips

        debug_log("S'ha llegit els paràmetres introduits")

        server_config = read_server_config(server_config_filename)
        debug_log(f"S'ha llegit el arxiu de configuració de servidor: {server_config_filename}")
        debug_log("(" + str(server_config) + ")")

        equips_dictionary = read_equips_file(equips_filename)
        debug_log(f"S'ha llegit el arxiu d'equips: {equips_filename}")

        initialize_sockets()
        wait_for_connections()

    except KeyboardInterrupt:
        sys.exit(1)


if __name__ == "__main__":
    main()
