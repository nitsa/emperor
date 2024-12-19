# Emperor

Emperor : ICMPv6 p2p Communication without Third Party (DeepSec 2024)

Ref 1 : https://deepsec.net/speaker.html#PSLOT732

Ref 2 : https://vimeo.com/deepsec/review/1035589680/19beeb7294

We are introducing a technique using ICMPv6 error messages that allows direct and autonomous P2P communication bypassing inherently the limitations imposed by router firewalls. The POC has been tested behind some home routers on Win10 machines with default software firewall settings. It also allows establishing P2P communication without the need of a 3rd party service to initiate that communication (like a STUN server). Communication is encrypted by using RC6 encrypting with hard-coded keys. It is advised to change those keys before using.

Please run emperor.py on both clients. Only requirement is for at least one of the 2 clients to know the destination IPv6 address of the other client, which should put in emperor.txt. Also, make sure source IPv6 address is fetched from correct network interface. Currently (emperor.py) it is been fetched from Wi-Fi.

In prior version emperor_v0.2.py the source and destination IPv6 addresses should be hard-coded.

Enjoy !



