import os
import sys
import random
import time

from bcode.bcoding import *

import binascii
import hashlib
import re
import urllib
import urllib.parse
import struct

import socket
from multiprocessing import Process
import threading


import requests


MODE_OVERRIDE = False
if len(sys.argv) > 3 and sys.argv[3] == "True":
    MODE_OVERRIDE = True


def btoi(x):
    return int.from_bytes(x, byteorder='big')

def itob(x, length):
    return (x).to_bytes(length, byteorder='big')

def ip_dot(byte_ip):
    return '.'.join([str(btoi(byte_ip) >> (i << 3) & 0xFF)
      for i in range(4)[::-1]])

def ip_b(dot_ip):
    dot_ip = dot_ip.split('.')
    s = (int(dot_ip[0]) << 24) + (int(dot_ip[1]) << 16) + (int(dot_ip[2]) << 8) + int(dot_ip[3])
    return itob(s, 4)

def port_b(port_bytes):
    return (bytes([port_bytes >> 8])) + (bytes([port_bytes & 255]))

def get_bits(bstr):
    for b in bstr:
        for i in reversed(range(8)):
            yield (b >> i) & 1

class Peer(object):
    def __init__(self, peerip, peerport, client_socket, address, peerid):
        self.ip = peerip
        self.port = peerport
        self.socket = client_socket
        self.address = address
        self.peer_id = peerid
        self.bitfield = [0]*len(bit_field)
        self.am_choking = 1
        self.am_interested = 0
        self.peer_choking = 1
        self.peer_interested = 0
        self.kathread = None

    def compact_status(self):
        return str(self.am_choking) + str(self.am_interested) + str(self.peer_choking) + str(self.peer_interested)

    def schedule_keepalive(self, stop):
        client = self.socket
        print("sending keepalive to peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send keepalive message")
            return

        message = (itob(0, 4))
        self.send_wrapper(client, message)

        if not stop:
            self.kathread = threading.Timer(120, self.schedule_keepalive, args=(stop))

    def handshake(self, peer):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print("handshaking with peer:", ip_dot(peer[0].encode()), int.from_bytes(peer[1].encode(), byteorder='big'))
        try:
            client.connect((ip_dot(peer[0].encode()), int.from_bytes(peer[1].encode(), byteorder='big')))
        except:
            print("couldnt connect to " + ip_dot(peer[0].encode()) + ":"+ str(btoi(peer[1].encode())))
            return
        message = (bytes([18]) + b'URTorrent protocol' +
                    bytes(8) + info_hash.digest() + peer_id.digest())

        self.send_wrapper(client, message)
        data = client.recv(1024)
        hn = client.getpeername()
        # print(( ip_b(hn[0]).decode(), port_b(hn[1]).decode()) in peer_list)
        # for i in peer_list:
        #     print(btoi(i[1].encode()))

        peer_list[( ip_b(hn[0]).decode(), port_b(hn[1]).decode())] = {"status" : (1,0,1,0), "peer_id" : data[1+18+8+20:], "bit_field" : [0]*len(file_hashes)}
        # print(hn[0], btoi(port_b(hn[1])))
        self.peer_id = data[1+18+8+20:]
        print("client responded with peerid:", binascii.hexlify(data[1+18+8+20:]))
        global peer_map

        if self.peer_id not in peer_map: # not the canonical object, set up ip info and client socket
            peer_map[self.peer_id] = self

        peer_map[self.peer_id].socket = client
        peer_map[self.peer_id].address = peer[0]
        peer_map[self.peer_id].ip = peer[0]
        peer_map[self.peer_id].port = peer[1]

        time.sleep(.1)
        peer_map[self.peer_id].send_bitfield()
        # self.kathread = threading.Timer(120, self.schedule_keepalive(False))
        # threading.Thread(target=peer_map[self.peer_id].listenToClient, args= (self.socket, self.address)).start()



    def re_handshake(self, client, msg):
        # client = self.socket
        global info_hash
        global peer_id

        lock = threading.Lock()
        with lock:
            message = (bytes([18]) + b'URTorrent protocol' +
                        bytes(8) + info_hash.digest() + peer_id.digest())

        self.send_wrapper(client, message)

        pid = msg[1+18+8+20:]
        self.peer_id = pid

        if self.peer_id not in peer_map: # not the canonical object, set up listening on old object
            peer_map[self.peer_id] = self
        threading.Thread(target=peer_map[self.peer_id].listenToClient, args=(client, None)).start()
        print("recieved handshake from peer:", binascii.hexlify(pid))

        ### Check with tracker and handshake all known
        command_announce()
        # print("handshaking new peers")
        peer_map[self.peer_id].handshake_new_peers()

    def handshake_new_peers(self):
        for ip_port in peer_list:
            exists = False
            if btoi(ip_port[1].encode()) == port_number:
                continue
            for p in peer_map:
                if peer_map[p].ip is not None and (peer_map[p].ip, peer_map[p].port) == ip_port:
                    exists = True
                    break
            if exists:
                continue
            print("sending out handshake to new peer:")
            self.handshake(ip_port)

    def update_choke(self, choke):
        client = self.socket
        print("sending choke message (" +str(choke) + ") to peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send choke message")
            return

        if choke == "choke":
            message = (itob(1, 4) + bytes([0]))
        else:
            message = (itob(1, 4) + bytes([1]))

        self.send_wrapper(sock, message)
        self.am_choking = 1 if choke == "choke" else 0

    def send_wrapper(self, sock, message):
        sock.sendall(message)
        if self.kathread is not None:
            kathread.cancel()
        kathread = threading.Timer(120, self.schedule_keepalive, args=(False))

    def update_interested(self, interested):
        client = self.socket
        print("sending interest message (" +str(interested) + ") to peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send interest message")
            return

        if interested == "interested":
            message = (itob(1, 4) + bytes([2]))
        else:
            message = (itob(1, 4) + bytes([3]))
        self.send_wrapper(client, message)
        self.am_interested = 1 if choke == "interested" else 0

    def send_bitfield(self):
        client = self.socket

        print("sending bitfield to peer:", ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send bitfield")
            return

        global bit_field
        print(''.join([str(i) for i in bit_field]))
        bf = ''.join([str(i) for i in bit_field])
        if len(bf) % 8 != 0:
            bf += '0'*(8 - len(bf) % 8)

        newbf = int(bf, 2).to_bytes(len(bf)//8, byteorder="big")

        # print(newbf)

        message = (itob(1 + len(newbf), 4) + bytes([5]) + newbf)
        # print(message)
        self.send_wrapper(client, message)


    def download_block(self, index):
        client = self.socket
        print("requesting block (" +str(index) + ") from peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send have message")
            return

        offset = 0
        print(final_piece_length, piece_length)
        pl = final_piece_length if index == (len(bit_field) - 1) else piece_length
        while offset < pl:
            blen = min(pl - offset, block_length)
            message = itob(13, 4) + bytes([6]) + itob(index, 4) + itob(offset, 4) + itob(blen, 4)
            self.send_wrapper(client, message)
            print(offset)
            print(blen)
            offset += block_length
            time.sleep(.001)


    def parse_bitfield(self, client, bitstr_data, length):
        bf = [int(i) for i in get_bits(bitstr_data)]
        bf = bf[:len(bit_field)] #bits per byte
        print("recieved bitfield from peer:", ''.join([str(i) for i in bf]))
        self.bitfield = bf
        self.update_bitfield()

    def update_bitfield(self):
        for i in range(0, len(bit_field)):
            if self.bitfield[i] == 1:
                piece_map[i].add(self.peer_id)
        download_from_peers()

    def send_have(self, bitindex):
        client = self.socket
        print("sending have message (" +str(bitindex) + ") to peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        if client == None:
            print("cant send have message")
            return

        message = (itob(5, 4) + bytes([4]) + itob(bitindex, 4))
        self.send_wrapper(client, message)

    def send_piece(self, piece_index, offset, length):
        if piece_index not in file_pieces:
            print("requested index not found")
        block = file_pieces[piece_index][offset:offset+length]

        print("sending piece message (" +str(piece_index) + ") to peer:" , ip_dot(self.ip.encode()), int.from_bytes(self.port.encode(), byteorder='big'))
        client = self.socket
        if client == None:
            print("cant send piece message")
            return

        print("sending piece", offset, length, len(block))
        message = itob(9 + len(block), 4) + bytes([7]) + itob(piece_index, 4) + itob(offset, 4) + block
        self.send_wrapper(client, message)

    def listenToClient(self, client, address, mode="standard"):
        if client == None:
            return
        size = 1024
        resid = None
        while True:
            try:
                if resid is not None and resid != b'':
                    data = resid + client.recv(size)
                    resid = None
                else:
                    data = client.recv(size)
                if data:
                    if b'URTorrent protocol' in data:
                        if len(data) > (1+18+8+20+20):
                            resid = data[1+18+8+20+20:]
                        self.re_handshake(client, data)
                        if mode == "temp":
                            return
                    else:
                        msg_len = btoi(data[:4])
                        if msg_len == 0:  # keep-alive
                            print("recieved keepalive")
                            if len(data) > (4):
                                resid = data[4:]
                            continue
                        if msg_len > block_length * 4:
                            print("something fucked up")
                            resid = None
                            continue
                        while len(data) < msg_len + 4:
                            data += client.recv(size)
                            print("poop")
                        if len(data) > msg_len + 4:
                            resid = data[msg_len + 4:]
                            data = data[:msg_len + 4]

                        msg_id = (data[4])
                        print("message id: " , msg_id)
                        if msg_id == 0:  #choke
                            self.peer_choking = 1
                        elif msg_id == 1: #unchoke
                            self.peer_choking = 0
                        elif msg_id == 2: #interested
                            self.peer_interested = 1
                        elif msg_id == 3: #notinterested
                            self.peer_interested = 0
                        elif msg_id == 4: #have
                            print("peer has " + str(btoi(data[5:])))
                            self.bitfield[btoi(data[5:])] = 1
                            print("new bitfield:", ''.join([str(i) for i in self.bitfield]))
                            self.update_bitfield()
                        elif msg_id == 5: #bitfield
                            self.parse_bitfield(client, data[5:], msg_len - 1)
                        elif msg_id == 6: #request
                            print("peer requesting " + str(btoi(data[5:9])))
                            self.send_piece(btoi(data[5:9]), btoi(data[9:13]), btoi(data[13:17]))
                        elif msg_id == 7: #piece
                            global piece_builder
                            print("recieved piece:", btoi(data[5:9]), "offset", btoi(data[9:13]))
                            if bit_field[btoi(data[5:9])] == 1:
                                print("already have piece")
                                continue
                            pce = piece_builder[btoi(data[5:9])]
                            offset = btoi(data[9:13])
                            prev = pce[0:offset]
                            new = data[13:]
                            old = pce[offset + len(new):]
                            piece_builder[btoi(data[5:9])] = prev + new + old
                            print(len(piece_builder[btoi(data[5:9])]))
                            check_hash(btoi(data[5:9]))
                        elif msg_id == 8: #cancel
                            pass

                else:
                    raise error('Client disconnected')
            except:
                client.close()
                return False


####  socket handling ######
####  source: SO      ######
class ThreadedServer(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        threading.Thread(target=self.listen).start()

    def listen(self):
        self.sock.listen(5)
        while True:
            client, address = self.sock.accept()
            client.settimeout(60 * 3)  #keep alive every 2 minutes
            ip = ip_b(client.getpeername()[0])
            port =port_b(client.getpeername()[1])
            peer = Peer(None, None, client, address, None)
            print("recieved connection from:",client.getpeername()[0])
            peer.listenToClient(client, address, mode = "temp")


if len(sys.argv) < 3:
    print("usage: urtorrent <portno> <filename.torrent>")
    exit(1)


port_number = int(sys.argv[1])
torrent_file_name = sys.argv[2]
actual_file_name = torrent_file_name.replace(".torrent", "")
bencoded = None
decoded = None
info_hash = None
peer_id = hashlib.sha1(b''.join(random.choice([b"a", b"b"]) for _ in range(10)))
tracker_ip = None
status_info = None
block_length = 16384
final_piece_length = None
piece_length = None
pending_blocks = None
file_pieces = {}
file_hashes = {}
peer_list = {}
piece_builder = {}
state = "leech"
bit_field = []
# maps peer_id's to peer objects
peer_map = {}
piece_map = []
TIMEOUT_SECONDS = 3
max_pending = 5
num_pending = 0


def init(filename):
    if not os.path.exists(filename):
        print( "Cannot find file: " + filename)
        exit(1)

    print(actual_file_name)
    global state
    if os.path.exists(actual_file_name) and not MODE_OVERRIDE:
        state = "seed"

    with open(filename, 'rb') as f:
        global bencoded
        bencoded = f.read()
        global decoded
        decoded = (bdecode(bencoded))

        global info_hash
        info_hash = hashlib.sha1(bencode(decoded["info"]))
        global tracker_ip
        tracker_ip = decoded["announce"]

        global file_hashes
        global bit_field
        pieces = split_into_hashes(decoded["info"]["pieces"])
        bit_field = [0]*len(pieces)
        global pending_blocks
        pending_blocks = [0]*len(pieces)
        for i in range(len(pieces)):
            piece_map.append(set({}))
        for i in pieces:
            file_hashes[pieces.index(i)] = i
            if state == "seed":
                bit_field[pieces.index(i)] = 1
        global piece_length
        piece_length = decoded["info"]["piece length"]
        total_length = decoded["info"]["length"]
        global final_piece_length
        final_piece_length = total_length - (total_length//piece_length)*piece_length

        global piece_builder
        for i in range(len(pieces) - 1):
            piece_builder[i] = bytes(piece_length)
        piece_builder[len(pieces) - 1] = bytes(final_piece_length)

def split_into_hashes(bstring):
    pieces = []
    while bstring != b'':
        pieces += [bstring[0:20]]
        bstring = bstring[20:]
    return pieces

def command_metainfo(filename):
    if not os.path.exists(filename):
        return "Cannot find file: " + filename

    # with open(filename, 'rb') as f:
    #     bencoded = f.read()
    #     decoded = (bdecode(bencoded))

    print("IP/port\t\t: " + "127.0.1.1" + '/' + str(port_number) )
    print("ID\t\t: " + str(peer_id.hexdigest()))
    print("metainfo file\t\t: " + filename)
    print("info\t\t: " + str(info_hash.hexdigest()))
    print("announce URL\t\t: " + decoded["announce"])
    print("file name\t\t: " + decoded["info"]["name"])
    piece_length = decoded["info"]["piece length"]
    print("piece length\t\t: " + str(decoded["info"]["piece length"]))
    pieces = split_into_hashes(decoded["info"]["pieces"])
    total_length = decoded["info"]["length"]
    print("file size\t\t: " + str(total_length) ,"(", str(len(pieces) - 1),"*", piece_length, "+", total_length - ((len(pieces) - 1) * piece_length),")" )
    print("pieces' hashes:")
    for i in pieces:
        print( str(pieces.index(i)) + " " + binascii.hexlify(i).decode('ascii'))


def command_announce():
    if state == "seed":
        params = {"info_hash" : info_hash.digest(), "peer_id" : peer_id.digest(), "port" : port_number,
            "uploaded": 0, "downloaded": 0, "left":0, "compact":1, "event":"started"}
    else:
        params = {"info_hash" : info_hash.digest(), "peer_id" : peer_id.digest(), "port" : port_number,
            "uploaded": 0, "downloaded": 0, "left": decoded["info"]["length"], "compact":1, "event":"started"}


    r = requests.get('http://' + tracker_ip + '/announce', params = params)

    # print(r.status_code)
    if r.status_code >= 400:
        print("tracker not found at " + tracker_ip)
        exit(1)
    global status_info
    status_info = bdecode(r.content)
    global peer_list
    peer_list = {}
    peers = status_info["peers"]
    while len(peers) >= 1:
        ip = peers[:4]
        port = peers[4:6]
        peer_list[(ip, port)] = None
        peers = peers[6:]

    # print(status_info)
    print_status()
    return r.text

def write_file():
    with open("ouput_" + actual_file_name, 'wb') as f:
        for i in range(0, len(bit_field)):
            f.write(file_pieces[i])
    print("torrent complete.")
    print("file written to ouput_" + actual_file_name)

def check_done():
    for i in bit_field:
        if i != 1:
            return False
    return True

def check_hash(piece_index):
    global num_pending
    if hashlib.sha1(piece_builder[piece_index]).digest() == file_hashes[piece_index]:
        print("hash complete")
        bit_field[piece_index] = 1
        file_pieces[piece_index] = piece_builder[piece_index]
        pending_blocks[piece_index] = 0
        num_pending -= 1
        download_from_peers()
        print("current bitfield:",''.join([str(i) for i in bit_field]))
        if check_done():
            write_file()
        return
    print("hash not correct")

def load_pieces():
    with open(actual_file_name, 'rb') as f:
        bytes_ = f.read()
        index = 0
        count = 0
        global file_pieces
        while index < len(bytes_):
            file_pieces[count] = bytes_[index:min(index+piece_length, len(bytes_))]
            if hashlib.sha1(file_pieces[count]).digest() != file_hashes[count]:
                print(count)
                print("file pieces not working")
                exit(1)
            count += 1
            index += piece_length

def command_show():
    global peer_map
    print("peer_ID \t\t\t\t\t| IP address   | Status | Bitfield\t\t")#| Down/s   | Up/s     | ")
    print("---------------------------------------")
    for p in peer_map:
        p2 = peer_map[p]
        print(binascii.hexlify(p2.peer_id), '\t|', ip_dot(p2.ip.encode()), ' | ', p2.compact_status() , ' | ', ''.join([str(i) for i in p2.bitfield]))

def print_status():
    if status_info == None:
        print("client not yet announced")
        return
    for key in ["min interval", "downloaded", "complete", "incomplete", "interval"]:
        if key not in status_info:
            status_info[key] = "NA"

    print("complete\t| downloaded\t| incomplete\t| interval\t| min interval")
    print("------------------------------------------------------------------------------")
    print(status_info["complete"],'\t\t|',status_info["downloaded"],'\t\t|',
            status_info["incomplete"],'\t\t|',status_info["interval"],'\t\t|',
            status_info["min interval"])
    print("------------------------------------------------------------------------------")

    if peer_list != {}:
        print("\nPeer List:")
        for peer in peer_list:
            # print(peer, type(peer[0]), type(peer[1]))
            print( ip_dot(peer[0].encode()) + '\t|\t' + str(int.from_bytes(peer[1].encode(), byteorder='big')))

def download_from_peers():
    print("downlaoding form peers")
    complete = True
    for i in range(len(bit_field)):
        if bit_field[i] == 0:
            complete = False
    if complete:
        return

    minseeds = 100000
    rarest = None
    global num_pending
    for i in range(0, len(piece_map)):
        if bit_field[i] == 1:
            continue
        if pending_blocks[i] != 0:
            if time.time() - pending_blocks[i] > TIMEOUT_SECONDS:
                pending_blocks[i] = 0
                num_pending -= 1
            else:
                continue
        if minseeds > len(piece_map[i]) and len(piece_map[i]) > 0:
            minseeds = len(piece_map[i])
            rarest = i

    if num_pending == max_pending:
        print("too many pending")
        return

    if rarest is None:
        return  # already have file or nothing to be done

    for p in piece_map[rarest]:
        break

    peer = peer_map[p]
    peer.download_block(rarest)
    num_pending += 1
    pending_blocks[rarest] = time.time()
    download_from_peers()

def sched_download(delay=1):
    download_from_peers
    if not check_done():
        threading.Timer(delay, sched_download, args=(delay,))



init(torrent_file_name)
if state == "seed":
    load_pieces()
# print(tracker_ip)
# command_metainfo('treatmelikeapirate.mp3.torrent')
command_announce()

server = ThreadedServer('127.0.0.1', port_number)



for i in peer_list:
    if ip_dot(i[0].encode()) == "127.0.0.1" and btoi(i[1].encode()) == port_number:
        continue
    peer = Peer(i[0], i[1], None, None, None)
    peer.handshake(i)



if state == "leech":
    sched_download(1)

# print(peer_id.hexdigest())

while True:
    next_command = input().replace("\n", "")
    if next_command == "announce":
        command_announce()
    elif next_command == "trackerinfo":
        print_status()
    elif next_command == "metainfo":
        command_metainfo(torrent_file_name)
    elif next_command == "show":
        command_show()
    else:
        print("command not available")
