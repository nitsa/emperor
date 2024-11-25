import sys, os
import _thread

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
        capture = sniff(filter="icmp6 && icmp6[0] = 4 && icmp6[1] = 1 && ip6 src " + str(dst), count=1)
        packet = capture[0]
        packet = bytes(packet)
        # print(packet)
        data = packet[62:]
        data = rc6.data_decryption_CBC(data, iv_data)
        print(Fore.GREEN + data.decode() + Fore.WHITE)

def sender(src, dst, data):

    # IPv6 packet
    IPv6_icmp = IPv6()
    IPv6_icmp.src = src
    IPv6_icmp.dst = dst
    
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

def main():
    
    clear_screen()
    
    print("                                               ")
    print(" __                     __       __            ")
    print("|_  _  _  _ _ _  _   _   _) _   (_    _|_ _ _  ")
    print("|__||||_)(-| (_)|   |_) /__|_)  __)\\/_)|_(-|||")
    print("      |             |      |       /           ")
    print("                                               ")
    print("                     v0.2                      ")
    print("                                               ")
    print("          .:! Greetings, mortal !:.            ")
    print("                                               ")
    print("  .: Type something to begin communication :.  ")
    print("")
    print("")
    print("")
    print("")
    
    # my IPv6
    src_ipv6 = "2a62:576:a402:33b5:469f:872:3f57:6b7a"
    
    # Destination IPv6
    dst_ipv6 = "8a02:886:a772:3543:465d:47e1:2303:5c6"
        
    # Set key
    key = b'Ksj%7tGvbmncFj@37%+0f'
    rc6 = RC6Encryption(key)
    
    # Set iv to 16 bytes
    iv_data = b'KfjcVm5^9dFkeCvn'
    
    # Start receiver in separate thread
    _thread.start_new_thread(receiver, (dst_ipv6, rc6, iv_data,))

    # Start sender
    while True:
        msg = input().encode('utf8')
        
        # Set custom iv (16 bytes) and encrypt
        iv, encrypt = rc6.data_encryption_CBC(msg, iv_data)
        sender(src_ipv6, dst_ipv6, encrypt)

if __name__ == "__main__":
    main()
