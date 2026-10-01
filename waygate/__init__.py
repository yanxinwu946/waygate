"""Waygate - a local proxy that leaves through Cloudflare WARP.

Layers (bottom to top):

    wireguard.py   Noise_IKpsk2 handshake + transport over UDP (the WARP tunnel)
    packets.py     raw IPv4 / TCP / UDP header encode + decode
    ipstack.py     user-space IP stack: TCP client, UDP sockets, ICMP sink
    dns.py         small DNS client that runs *inside* the tunnel
    socks5.py      asyncio SOCKS5 server bridged onto the user-space stack
    warp.py        WARP registration API + on-disk identity
    cli.py         command line entry point
"""

__version__ = "1.0.0"
