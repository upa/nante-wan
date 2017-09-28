
### なんちゃってSD-WAN

Something like SD-WAN based on EVPN/VXLAN over DMVPN powered by FRRouting.



#### 1. Prepare hub router

A hub router performs a Route Reflector (RR) for EVPN/VXLAN and Next
Hop Server for DMVPN. FRRouting can perform those roles (NOTE:
--enable-cumulus option in configure script is required to use EVPN).

Example configurations are show below.
- Hub Host information
    - Physical interface : eth0
    - Physical address : 192.168.0.100
    - DMVPN interface : gre1
    - DMVPN inner address : 10.0.0.100

From a viewpoint of overlay networking like LISP, we can regard
192.168.0.100 as a locator address and 10.0.0.100 as an identifier of
the hub router.

DMVPN (nhrpd) provides a dynamic multi-point virtual network over
physical networks such as the Internet. DMVPN leverages IPsec, so that
this DMVPN can cross NAT boxes. bgpd listen on gre1 interface and
exchange route informations over the DMVPN. VXLAN encapsulated packets
are also delivered through the DMVPN.



```shell-session
# First of All, create a gre interface for DMVPN.
# Details are described in the document https://github.com/FRRouting/frr/blob/master/nhrpd/README.nhrpd
ip tunnel add gre1 mode gre key 2501 ttl 64 dev eth0
ip addr add 10.0.0.100/32 dev gre1
ip link set gre1 up
iptables -A FORWARD -i gre1 -o gre1 \
        -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 \
        --hashlimit-mode srcip,dstip --hashlimit-srcmask 16 \
        --hashlimit-dstmask 16 --hashlimit-name loglimit-0 \
        -j NFLOG --nflog-group 1 --nflog-range 128
```

```
# FRR EVPN/VXLAN RR and DMVPN config
!
interface gre1
 description DMVPN-Inner
 ip address 10.0.0.100/32
 ip nhrp network-id 2501
 ip nhrp redirect
 tunnel protection vici profile dmvpn
 tunnel source eth0
!
router bgp 65000
 bgp router-id 10.0.0.100
 no bgp default ipv4-unicast
 bgp cluster-id 0.0.0.1
 neighbor evpn-test peer-group
 neighbor evpn-test remote-as 2501
 neighbor evpn-test update-source gre1
 neighbor evpn-test capability extended-nexthop
 bgp listen range 10.0.0.0/24 peer-group evpn-test
 !
 address-family l2vpn evpn
  neighbor evpn-test activate
  neighbor evpn-test route-reflector-client
  advertise-all-vni
 exit-address-family
 vnc defaults
  response-lifetime 3600
  exit-vnc
!
```

```
# ipsec.conf for the patched strongswan
conn dmvpn
        left=192.168.0.100
        right=%any
        leftprotoport=gre
        rightprotoport=gre
        type=transport
        authby=secret
        auto=add
        keyingtries=%forever
```


```
# ipsec.secrets
: PSK "ipsec password"
```



#### 2. Prepare spoke router

Nante-WAN provides a docker images that performs a spoke router of
EVPN/VXLAN over DMVPN networks. This docker images must runs on host
network stacks to manipulate routing table entries even if it is
insecure.

To execute the docker image, 1. create gre interface for DMVPN as same
as the hub host and 2.  create a config file for nante-WAN.

- Example spoke host information
    - Physical interface : eth0
    - Physical address : 192.168.0.10
    - DMVPN interface : gre1
    - DMVPN inner address : 10.0.0.10


```shell-session
# @ Spoke Host
ip tunnel add gre1 mode gre key 2501 ttl 64 dev eth0
ip addr add 10.0.0.10/32 dev gre1
ip link set gre1 up
iptables -A FORWARD -i gre1 -o gre1 \
        -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 \
	--hashlimit-mode srcip,dstip --hashlimit-srcmask 16 \
	--hashlimit-dstmask 16 --hashlimit-name loglimit-0 \
	-j NFLOG --nflog-group 1 --nflog-range 128


# nante-wan.conf is an example to configure the spoke host in accordance with this example.
cat nante-wan.conf


# pull the docker image and execute it.
# After docker-run, frr and ipsec daemons start
docker pull upaa/nante-wan
docker run -it --rm --privileged --net=host -v `pwd`/nante-wan.conf:/etc/nante-wan.conf upaa/nante-wan
Starting Frr daemons (prio:10):. zebra2017/09/28 10:30:12 warnings: ZEBRA: Disabling MPLS support (no kernel support)
. bgpd. nhrpdnhrpd[36]: nhrpd 3.1-dev-Nante-WAN-g67c0a92 starting: vty@2610
.
Starting Frr monitor daemon: watchfrrwatchfrr[42]: watchfrr 3.1-dev-Nante-WAN-g67c0a92 watching [zebra bgpd nhrpd]
watchfrr[42]: bgpd state -> up : connect succeeded
watchfrr[42]: zebra state -> up : connect succeeded
watchfrr[42]: nhrpd state -> up : connect succeeded
watchfrr[42]: Watchfrr: Notifying Systemd we are up and running
.
Exiting from the script
Starting strongSwan 5.5.1dr1 IPsec [starter]...
ipsec_starter[46]: Starting strongSwan 5.5.1dr1 IPsec [starter]...

root@frr3:/# ipsec_starter[59]: charon (62) started after 20 ms
root@frr3:/#
root@frr3:/#


# you can see and operate frr through vtysh in the container.
```

