
Nante-WAN: なんちゃってSD-WAN
==============================

Nante-WAN is yet another SD-WAN solution by open source software:
Linux and [FRRouting](https://frrouting.org/). Nante-WAN provides
NAT-traversal, Multipoint, Encrypted Layer-2 overlay networks by using
DMVPN (Dynamic Multipoint VPN) and VXLAN.

The data plane of Nante-WAN is VXLAN over DMVPN/IPsec overlay network.
DMVPN provides multipoint layer-3 overlay, and IPsec provides packet
encryption and NAT-traversal. Moreover, VXLAN encapsulates Ethernet
frames in IP headers, which are inner IP headers of the DMVPN overlay.

The control plane of Nante-WAN is composed of FRRouting that is a fork
of Quagga. Nante-WAN uses EVPN for exchanging VXLAN FDB, and NHRP for
DMVPN.


Nante-WAN components are packaged as docker containers, and they run
on Ubuntu 17.10. So, you can (easily?) test this yet another SD-WAN in
your own virtual machine environments.



## Nante-WAN components

#### Fig.1 Overview of Nante-Wan overlay
![Overview of Nante-WAN Overlay](https://raw.githubusercontent.com/wiki/upa/nante-wan/fig/nante-wan-overlay.png)


As shown in Fig.1, a Nante-WAN overlay comprises customer edge (CE)
nodes, Route Server, and Config Server.

- **CE node**: CE nodes accommodate edge networks and deliver Ethernet
  frames from the edge networks to distant and proper destination CEs.

- **Route Server**: Route Server is BGP Route Reflector. A route
  server establishes iBGP connections with all CEs, and exchange EVPN
  routes as a control plane for VXLAN overlays.

- **Config Server**: Config Server is an HTTP server. CE nodes
  regurarly fetch bridge configuration files from the config server
  across the DMVPN overlay. Moreover, when a config file for a CE node
  is changed, the config server notifies the CE.


CE nodes constructs VXLAN over DMVPN overlay using Route Server as
IPsec anchor, Next Hop Resolation on DMVPN, and RR for EVPN. Bridging
configuration on CE nodes are centralized in Config Server. Under this
control, CE nodes deliver Ethernet frames from edge networks to proper
CE nodes across the Internet.




## Example setup


#### Fig.2 Example test environment.

![Example test environment](https://raw.githubusercontent.com/wiki/upa/nante-wan/fig/nante-wan-test-env.png)

Fig.2 shows an example test environment this README describes. Three
CE nodes (CE 1 ~ 3) and a server for the route and config server roles
are Ubuntu 17.10. All nodes are connected to the network
192.168.0.0/24 through Ethernet interface 'eth0'. This network
performs an underlay network, e.g, the Internet.

Each node has a 'gre1' interface. The 'gre1' interface is an entry
point to a DMVPN overlay network. Each gre1 interface has a unique /32
IP address. Those /32 IP addresses on the DMVPN overlay are used for
messaging between CEs, route and config servers.

**Note:** In the example environment, instead of physical ports, we
use network namespace and veth interface as an edge network
(172.16.0.0/24, depicted as orange boxes in Fig.2).

After the Nante-WAN overlay is Up, all namespaces will be connected as
a single layer-2 segment across the underlay network. Then you can
ping from any namespaces to others.


How to make an edge network namespace is shown below.
```bash
# change edge_addr accordance with nodes.
edge_addr=172.16.0.1/24

ns=edge-network

ip link add vetha type veth peer name vethb
ip netns add $ns
ip link set dev vethb netns $ns

ip link set dev vetha up
ip netns exec $ns ip link set dev vethb up
ip netns exec $ns ip link set dev lo up
ip netns exec $ns ip addr add dev vethb $edge_addr
```

#### List of IP Addresses in this example test environment.
| Node                | eth 0           | gre1         | vethb         |
|:--------------------|:----------------|:-------------|:--------------|
| CE1                 | 192.168.0.1/24  | 10.0.0.1/32  | 172.16.0.1/24 |
| CE2                 | 192.168.0.2/24  | 10.0.0.2/32  | 172.16.0.2/24 |
| CE3                 | 192.168.0.3/24  | 10.0.0.3/32  | 172.16.0.3/24 |
| Route/Config Server | 192.168.0.10/24 | 10.0.0.10/32 | none          |



### 1. Edit nante-wan.conf 

First of all, clone Nante-WAN repository and edit
[nante-wan.conf](https://github.com/upa/nante-wan/blob/master/nante-wan.conf)

```shell-session
# at all nodes,
ce1:$ git clone https://github.com/upa/nante-wan.git
ce1:$ cd nante-wan
ce1:$ vim nante-wan.conf
```

nante-wan.conf is configuration file for Nante-WAN. Alhtough dozens of
parameters exist, only a few are important. The nante-wan.conf for
this example environment is shown below.

```
# Nante-WAN example config file

[general]
dmvpn_addr	= 10.0.0.X

[config_fetch]
timeout		= 5
interval	= 3600
failed_interval	= 5

[routing]
wan_interface	= eth0
dmvpn_interface	= gre1
as_number	= 65000
nhs_nbma_addr	= 192.168.0.10
nhs_addr	= 10.0.0.10
rr_addr		= 10.0.0.10
bgp_range	= 10.0.0.0/16
ipsec_secret	= hogehogemogamoga
gre_key		= 1
gre_ttl		= 64


[portconfig]
br_interface	= bridge
json_url_prefix	= http://10.0.0.10/portconfig
bind_port	= 8080

[ebconfig]
br_interface    = bridge
json_url_prefix = http://10.0.0.10/ebconfig
bind_port       = 8081
```

The most important parameter is **dmvpn_addr**. **dmvpn_addr**
parameter is different from other nodes. It is 10.0.0.1 on CE1, and
10.0.0.2 on the route/config server. **wan_interface** should be
changed for a proper interface name according as machine
environment. If it is enp1s0 in your environment, *wan_interface*
should be enp1s0.


Other parameters are identical among all nodes regardless of node
types (CE, route or config server).


#### Note

**nhs_nbma_addr** and **nhs_addr** are NHRP configurations. They
indicate IP addresses of a route server node on underlay (eth0) and
DMVPN overlay (gre1). **rr_addr** is an IP address that iBGP on CEs
connect to. Thus, rr_addr is also an IP address of a route server on
DMVPN overlay.




### 2. Pull containers

At CE nodes,
```shell-session
ce1:$ docker pull upaa/nante-wan-routing
ce1:$ docker pull upaa/nante-wan-portconfig
```

At the route and config server,
```shell-session
server:$ docker pull upaa/nante-wan-route-server
server:$ docker pull upaa/nante-wan-config-serger
```

Roles of the containers are

- routing: Routing Container. It contains FRRouting for EVPN and NHRP,
  and StrongSwan for IPsec.

- portconfig: Port Configuration Container. This container regularly
  fetches port configuration file from a config server and configure
  bridge interfaces in accordance with the file.

- route-server: Route Server Container. It contains FRRouting and
  StrongSwan. It performs Next Hop Server of NHRP and Route Reflector
  for EVPN/VXLAN.

- config-server: Config Server Container: It performs Web server to
  distribute configuration files. If a config file is chenged, a
  process notifies the CE using inotify.


All containers contains config rendering scripts. These scripts
generate specific configuration files, for example, frr.conf and IPsec
configuration, from nante-wan.conf. Therefore, you can only run
containers with nante-wan.conf to start Nante-WAN without editting
specific configurations.



### 3. Run containers

nante-wan/start.py does all things to start Nante-WAN at nodes.

* create GRE interface
* create Bridge interface
* setup NFLOG for NHRP redirect/shortcut
* run containers


At the route/config server node,
```shell-session
# make a directory to store config files.
server:$ mkdir html
server:$ sudo ./start.py --route-server --config-server --config-dir html nante-wan.conf
```

At CE nodes,
```
ce1:$ sudo ./start.py nante-wan.conf
```


start.py shows executing commands like below.

```shell-session
ce2:$ sudo ./start.py nante-wan.conf
# Setup GRE Interface
#   wan_interface   : eth0
#   dmvpn_interface : gre1
#   dmvpn_addr      : 10.0.0.2
modprobe af_key
/bin/ip tunnel add gre1 mode gre key 1 ttl 64 dev eth0
/bin/ip addr flush gre1
/bin/ip addr add 10.0.0.2/32 dev gre1
/bin/ip link set gre1 up
# Setup Bridge Interface
#   br_interface : bridge
/bin/ip link add bridge type bridge vlan_filtering 1
/bin/ip link set dev bridge up
# Setup NFLOG
/sbin/iptables -A FORWARD -i gre1 -o gre1 -m hashlimit --hashlimit-upto 4/minute --hashlimit-burst 1 --hashlimit-mode srcip,dstip --hashlimit-srcmask 16 --hashlimit-name loglimit-0 -j NFLOG --nflog-group 1 --nflog-size 128
/sbin/iptables -P FORWARD ACCEPT
# Start Nante-WAN Docker Containers
/usr/bin/docker run -dt --rm --privileged --net=host -v /home/upa/work/nante-wan/nante-wan.conf:/etc/nante-wan.conf -v /dev/log:/dev/log upaa/nante-wan-routing
/usr/bin/docker run -dt --rm --privileged --net=host -v /home/upa/work/nante-wan/nante-wan.conf:/etc/nante-wan.conf -v /dev/log:/dev/log upaa/nante-wan-portconfig
```

And, you can verify EVPN and IPsec status like following.

```shell-session
ce2:$ docker ps
CONTAINER ID        IMAGE                       COMMAND                  CREATED             STATUS              PORTS               NAMES
b6b4fdd4e57e        upaa/nante-wan-portconfig   "/bin/sh -c 'bash ..."   2 seconds ago       Up 1 second                             hardcore_bell
7a461646c69b        upaa/nante-wan-routing      "/bin/sh -c 'bash ..."   2 seconds ago       Up 1 second                             compassionate_bohr
$ docker exec -it 7a vtysh
ce2# show bgp l2vpn evpn summary 
BGP router identifier 10.0.0.2, local AS number 65000 vrf-id 0
BGP table version 0
RIB entries 5, using 760 bytes of memory
Peers 1, using 19 KiB of memory
Peer groups 1, using 64 bytes of memory

Neighbor        V         AS MsgRcvd MsgSent   TblVer  InQ OutQ  Up/Down State/P
fxRcd
10.0.0.10       4      65000       8       6        0    0    0 00:01:18        
    2

Total number of neighbors 1
ce2:# exit
$ docker exec -it 7a ipsec status
Security Associations (1 up, 0 connecting):
       dmvpn[1]: ESTABLISHED 2 minutes ago, 192.168.0.2[192.168.0.2]...192.168.0.10[192.168.0.10]
       dmvpn{1}:  INSTALLED, TRANSPORT, reqid 1, ESP SPIs: c86df829_i cf9c192e_o
       dmvpn{1}:   192.168.0.2/32[gre] === 192.168.0.10/32[gre]

$
```



### 4. Put configuration files at config server

After containers run on all nodes, DMVPN/IPsec overlay is established,
and BGP EVPN starts VXLAN FDB exchange. Next step is distribuitng
bridge configuration files to CEs.

CEs try to fetch their configuration files from URL specified by
**json_url_prefix** on [portconfig] section in nante-wan.conf. The URL
is **[json_url_prefix]/[dmvpn_addr].json**. For example, CE1 accesses
*http://10.0.0.10/portconfig/10.0.0.1.json*, and CE2 accesses
*http://10.0.0.10/portconfig/10.0.0.2.json* (10.0.0.10 is dmvpn_addr
of config server).

The DocumentRoot of config server container is the directory specified
by **--config-dir** option of start.py. So, *html* in this case (see
step 3).


An example for bridge configuraiton file for this environment is shown
below. As you can see, this file indicates that the port vetha is
untagged port and it belongs to vlan 99. If an CE has multiple ports
or you want to configure a port as tagged, please modify the json as
you might have guessed.

```json
{
	"name" : "bridge",
	"ports" : [
		{
		       	"name" : "vetha", 
			"tagged" : false,
			"vlans" :  [ 99 ]
		}
	]
}
```

After place config files in *html/portconfig* directory, bridge
interfaces on all CE nodes are configured automatically.

At config server,
```shell-session
server:$ cat << EOF > example.json
heredoc% { "name" : "bridge", "ports" : [ { "name": "vetha", "tagged": false, "vlans": [ 99 ] } ] }
heredoc% EOF
server:$ cp example.json html/port/10.0.0.1.json
server:$ cp example.json html/port/10.0.0.2.json
server:$ cp example.json html/port/10.0.0.3.json
```


At CE nodes, verify vlan 99 is created and vetha is configured as
tagged vlan 99.

```shell-session
ce1:$ bridge vlan show
port	vlan ids
docker0	 1 PVID Egress Untagged

vetha	 1 Egress Untagged
	 99 PVID Egress Untagged

bridge	 1 PVID Egress Untagged
	 99

vxlan99	 1 Egress Untagged
	 99 PVID Egress Untagged
```


Then, you can ping from any edge network namespaces from others across
VXLAN over DMVPN overlay.

```shell-session
sudo ip netns exec edge-network bash
ce1:# ifconfig
lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
        inet 127.0.0.1  netmask 255.0.0.0
        inet6 ::1  prefixlen 128  scopeid 0x10<host>
        loop  txqueuelen 1000  (Local Loopback)
        RX packets 0  bytes 0 (0.0 B)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 0  bytes 0 (0.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

vethb: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.16.0.1  netmask 255.255.255.0  broadcast 0.0.0.0
        inet6 fe80::845c:d0ff:fe82:2cc6  prefixlen 64  scopeid 0x20<link>
        ether 86:5c:d0:82:2c:c6  txqueuelen 1000  (Ethernet)
        RX packets 859  bytes 55960 (55.9 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 1295  bytes 115470 (115.4 KB)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

ce1:# ping 172.16.0.2
PING 172.16.0.2 (172.16.0.2) 56(84) bytes of data.
64 bytes from 172.16.0.2: icmp_seq=1 ttl=64 time=1.39 ms
^C
--- 172.16.0.2 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 1.390/1.390/1.390/0.000 ms
ce1# ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
^C
--- 172.16.0.3 ping statistics ---
2 packets transmitted, 0 received, 100% packet loss, time 1005ms

ce1:# ping 172.16.0.3
PING 172.16.0.3 (172.16.0.3) 56(84) bytes of data.
64 bytes from 172.16.0.3: icmp_seq=1 ttl=64 time=2.03 ms
64 bytes from 172.16.0.3: icmp_seq=2 ttl=64 time=0.875 ms
^C
--- 172.16.0.3 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 1001ms
rtt min/avg/max/mdev = 0.875/1.456/2.038/0.582 ms
ce1# 
```




### Next Step

#### Adding new CE node

It is very easy. copy the nante-wan.conf to new node, change
**dmvpn_addr**, and `start.py nante-wan.conf`.


#### Changing bridge configuration of CE nodes

Edit portconfig/[CE's dmvpn_addr].json in the config directory in
your config server.


#### Web interface

Nante-WAN does not provide any wev interfaces. But, it is easy to make
your own web interface. What your web interface must do is, putting
and updating config json files.


#### Firewall

The ebconfig container provides L4 ACL and MAC address filtering
functions.



### Contact

upa at haeena.net