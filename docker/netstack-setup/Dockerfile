FROM ubuntu:17.04

ARG workdir="/root"

RUN apt-get update && apt-get install -y \
	python3 iproute2 iptables kmod

ADD start.py ${workdir}/start.py

CMD [ "python3", "/root/start.py", "--network-only", "/etc/nante-wan.conf" ]
