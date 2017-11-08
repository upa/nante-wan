FROM ubuntu:17.04

ARG workdir="/root"

RUN apt-get update && apt-get install -y \
	iproute2 python3 python3-requests python3-flask ebtables

# setup ebconfig
ADD ebconfig.py ${workdir}/ebconfig.py
ADD getip.py ${workdir}/getip.py

CMD bash -c "/root/ebconfig.py -b `/root/getip.py gre1` -p 8080 -u http://10.0.0.0/ebconfig/`/root/getip.py gre1`.json"
