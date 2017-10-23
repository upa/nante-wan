FROM ubuntu:17.04

ARG workdir="/root"

# install required packages
RUN apt-get update && apt-get install -y \
	iproute2 python3 python3-requests python3-flask


# setup sdwconfig
ADD sdwconfig.py ${workdir}/sdwconfig.py

CMD bash -c "/root/sdwconfig.py -c /etc/sdwconfig.conf"
