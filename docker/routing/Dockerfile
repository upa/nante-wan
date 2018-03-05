FROM ubuntu:17.10

ARG workdir="/root"

# install required packages and usuful applications
RUN apt-get update && apt-get install -y \
	wget iputils-ping iproute2 kmod \
	git autoconf automake libtool make gawk libreadline-dev \
	texinfo dejagnu pkg-config libpam0g-dev libjson-c-dev bison flex \
	python-pytest libc-ares-dev python3-dev libsystemd-dev	\
	libgmp-dev openssl gperf python3-jinja2	

# setup FRRouting with the cumulus extension for EVPN/VXLAN
RUN cd ${workdir}	\
	&& groupadd -g 92 frr	\
	&& groupadd -r -g 85 frrvty	\
	&& adduser --system --ingroup frr --home /var/run/frr/	\
	   --gecos "FRR suite" --shell /sbin/nologin frr	\
	&& usermod -a -G frrvty frr	\
	&& git clone https://github.com/frrouting/frr.git frr	\
	&& cd frr	\
	&& git checkout -b itworks 67c0a9206ce9b50dacb6561e7dccdc0ae8e7fc43 \
	&& ./bootstrap.sh	\
	&& ./configure \
	    --prefix=/usr \
	    --enable-exampledir=/usr/share/doc/frr/examples/ \
	    --localstatedir=/var/run/frr \
	    --sbindir=/usr/lib/frr \
	    --sysconfdir=/etc/frr \
	    --enable-watchfrr \
	    --enable-multipath=64 \
	    --enable-user=frr \
	    --enable-group=frr \
	    --enable-vty-group=frrvty \
	    --enable-configfile-mask=0640 \
	    --enable-logfile-mask=0640 \
	    --enable-systemd=yes \
	    --with-pkg-git-version \
	    --with-pkg-extra-version=-Nante-WAN	\
	    --enable-cumulus	\
	&& make	-j 4\
	&& make install	\
	&& install -m 755 -o frr -g frr -d /var/log/frr	\
	&& install -m 775 -o frr -g frrvty -d /etc/frr	\
	&& install -m 640 -o frr -g frr /dev/null /etc/frr/zebra.conf	\
	&& install -m 640 -o frr -g frr /dev/null /etc/frr/bgpd.conf	\
	&& install -m 640 -o frr -g frr /dev/null /etc/frr/nhrpd.conf	\
	&& install -m 640 -o frr -g frrvty /dev/null /etc/frr/vtysh.conf \
	&& install -m 644 tools/frr.service /etc/systemd/system/frr.service \
	&& install -m 644 tools/etc/default/frr /etc/default/frr	\
	&& install -m 644 tools/etc/frr/daemons /etc/frr/daemons	\
	&& install -m 644 tools/etc/frr/daemons.conf /etc/frr/daemons.conf \
	&& install -m 644 tools/etc/frr/frr.conf /etc/frr/frr.conf	\
	&& install -m 644 -o frr -g frr tools/etc/frr/vtysh.conf \
					/etc/frr/vtysh.conf \
	&& rm -f /etc/frr/daemons

ADD daemons /etc/frr/daemons

# setup StrongSwan
RUN cd ${workdir}	\
	&& git clone -b tteras --depth=1 \
		git://git.alpinelinux.org/user/tteras/strongswan
RUN cd ${workdir}/strongswan	\
	&& autoreconf -i || true	\
	&& autoconf		\
	&& autoreconf -i	\
	&& ./configure		\
	&& make	-j 4 || true	\
	&& make	-j 4 || true	\
	&& make	-j 4		\
	&& make install		\
	&& rm -f /usr/local/etc/ipsec.conf
ADD ipsec.conf /usr/local/etc/ipsec.conf

# setup Config Render
ADD templates ${workdir}/templates
ADD config-render.py ${workdir}/config-render.py


CMD bash -c "/root/config-render.py /etc/nante-wan.conf && /usr/lib/frr/frr start && ipsec start && bash"
