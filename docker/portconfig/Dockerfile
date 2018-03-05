FROM ubuntu:17.10

ARG workdir="/root"

# install required packages
RUN apt-get update && apt-get install -y \
	iproute2 python3 python3-requests python3-flask


# setup sdwconfig
ADD portconfig.py ${workdir}/portconfig.py

CMD bash -c "/root/portconfig.py /etc/nante-wan.conf"
