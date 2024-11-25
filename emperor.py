import sys, os
import _thread
import socket
import time

# pip install psutil
import psutil

# pip install scapy
from scapy.all import *
import logging

# Get rid of scapy warnings
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# pip install colorama
from colorama import Fore, Back, Style

# pip install RC6Encryption
from RC6Encryption import RC6Encryption
  
# Clear screen    
def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def receiver(dst, rc6, iv_data):
    while True:
        # Report only specific packet from specific ipv6 source address
        capture = sniff(filter="icmp6 && icmp6[0] = 4 && icmp6[1] = 1 && ip6 dst " + str(dst), count=1)
        packet = capture[0]
        packet = bytes(packet)
        # print(packet)
        data = packet[62:]
        
        # Check ID
        if (ord(data[0:1]) == 0xBE and ord(data[1:2]) == 0xEF):
            data = data[2:]
            data = rc6.data_decryption_CBC(data, iv_data)
            
            # Message type is comms data
            if (data[0:1].decode() == '!'):
                print(Fore.GREEN + data[1:].decode() + Fore.WHITE)
                         
            # Message type is p2p ip sync
            if (data[0:1].decode() == '?'):
                
                # update destination ipv6
                global dst_ipv6
                dst_ipv6 = data[1:].decode()
            
                # update local db
                f = open("emperor.txt","w")
                f.write(dst_ipv6)
                f.close()
                        

def sender(src, dst, data):

    # IPv6 packet
    IPv6_icmp = IPv6()
    IPv6_icmp.src = src
    IPv6_icmp.dst = dst
    # IPv6_icmp.hlim = 1
    
    # ICMPv6 following
    IPv6_icmp.nh  = 58

    # ICMPv6 ParamProblem message type
    ICMPv6_ParamProblem      = ICMPv6ParamProblem()
    ICMPv6_ParamProblem.type = 4
    ICMPv6_ParamProblem.code = 1
    ICMPv6_ParamProblem.ptr  = 0
    
    # Set verbose to False to avoid printing information messages
    packet = IPv6_icmp/ICMPv6_ParamProblem/Raw(load=data)
    send(packet, count=1, verbose=False)
    
    
def p2p_ip_sync(src, dst, data):
    while True:
        # Set up ID before send
        data_id = b'\xBE\xEF' + data
        sender(src, dst, data_id)
        time.sleep(5)
    
    
def get_ipv6_address_from_nic(interface):
    interface_addrs = psutil.net_if_addrs().get(interface) or []
    for snicaddr in interface_addrs:
        if snicaddr.family == socket.AF_INET6:
            return snicaddr.address


def main():
    
    clear_screen()
    
    print("                                               ")
    print(" __                     __       __            ")
    print("|_  _  _  _ _ _  _   _   _) _   (_    _|_ _ _  ")
    print("|__||||_)(-| (_)|   |_) /__|_)  __)\\/_)|_(-|||")
    print("      |             |      |       /           ")
    print("                                               ")
    print("                     v0.53                     ")
    print("                                               ")
    print("          .:! Greetings, mortal !:.            ")
    print("                                               ")
    print("  .: Type something to begin communication :.  ")
    print("")
    print("")
    print("")
    print("")
    
    # my IPv6
    src_ipv6 = get_ipv6_address_from_nic("Wi-Fi")
    
    # Destination IPv6 from local db
    global dst_ipv6
    f = open("emperor.txt","r")
    dst_ipv6 = f.read().strip()
    f.close()
    
    # Set key
    key = b'Ksj%7tGvbmncFj@37%+0f'
    rc6 = RC6Encryption(key)
    
    # Set iv to 16 bytes
    iv_data = b'KfjcVm5^9dFkeCvn'
    
    # Start receiver in separate thread
    _thread.start_new_thread(receiver, (src_ipv6, rc6, iv_data,))
    
    # Start p2p ip sync on separate thread
    msgtype     = '?'
    msg         = msgtype + src_ipv6
    msg         = msg.encode('utf8')
    iv, encrypt = rc6.data_encryption_CBC(msg, iv_data)
    _thread.start_new_thread(p2p_ip_sync, (src_ipv6, dst_ipv6, encrypt,))

    # Start sender
    while True:
        # Get message from user
        msg = input()
        
        # Set message type to comms data
        msgtype = '!'
        msg     = msgtype + msg
        msg     = msg.encode('utf8')
        
        # Set custom iv (16 bytes) and encrypt
        iv, encrypt = rc6.data_encryption_CBC(msg, iv_data)
        
        # Set up ID before send
        encrypt = b'\xBE\xEF' + encrypt
        sender(src_ipv6, dst_ipv6, encrypt)

if __name__ == "__main__":
    main()
    