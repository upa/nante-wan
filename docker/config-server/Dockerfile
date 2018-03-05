FROM ubuntu:17.10

ARG workdir="/root"

RUN apt-get update && apt-get install -y \
	nginx	\
	python3-jinja2	\
	python3-pyinotify	\
	python3-requests	\
	&& rm -rf /etc/nginx/sites-enabled/default

# add Config Render
ADD templates ${workdir}/templates
ADD config-render.py ${workdir}/config-render.py

# add kick-update
ADD kick-update.py ${workdir}/kick-update.py

CMD bash -c "/root/config-render.py /etc/nante-wan.conf && nginx && /root/kick-update.py -c /etc/nante-wan.conf -d /var/www/html"
