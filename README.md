
Nante-WAN: なんちゃってSD-WAN
==============================

Nante-WAN is yet another SD-WAN solution by open source software:
Linux and [FRRouting](https://frrouting.org/). Nante-WAN provides
NAT-traversal, Multipoint, Encrypted Layer-2 overlay networks by using
DMVPN (Dynamic Multipoint VPN) and VXLAN.

The data plane of Nante-WAN is VXLAN over DMVPN/IPsec overlay network
for achieving such functionalities. DMVPN provides multipoint layer-3
overlay, and IPsec provides packet encryption and
NAT-traversal. Moreover, VXLAN encapsulates Ethernet frames in IP
headers, which are inner IP headers of the DMVPN overlay.

The control plane of Nante-WAN is composed of FRRouting that is a fork
of Quagga. Nante-WAN uses EVPN for VXLAN FDB exchange and NHRP for
DMVPN.


#### Overview of Nante-Wan overlay
![Overview of Nante-WAN Overlay](https://raw.githubusercontent.com/wiki/upa/nante-wan/fig/nante-wan-overlay.png)



## Quick Start

Nante-WAN edge device components are packaged as docker
containers. So, you can (easily?) test this yet another SD-WAN.


### 1. Setup Route Reflector and Next Hop Server

[RR/NHRP description here]


### 2. Prepare a config server (a.k.a orchestrator)

[Config server description here]


### 3. Edit nante-wan.conf 

[Config file description here]

```bash
$ git clone https://github.com/upa/nante-wan.git
$ cd nante-wan
$ vim nante-wan.conf
```


### 4. Run

start.py does all things to start nante-wan at CE.

* create GRE interface
* create Bridge interface
* setup NFLOG for NHRP redirect/shortcut
* run containers


```bash
$ docker pull upaa/nante-wan-routing
$ docker pull upaa/nante-wan-portconfig

# in nante-wan directory
$ sudo ./start.py nante-wan.conf
```


