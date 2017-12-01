FROM ubuntu:17.04

ARG workdir="/root"

RUN apt-get update && apt-get install -y \
	nginx	\
	python3-jinja2	\
	&& rm -rf /etc/nginx/sites-enabled/default

# setup Config Render
ADD templates ${workdir}/templates
ADD config-render.py ${workdir}/config-render.py

CMD bash -c "/root/config-render.py /etc/nante-wan.conf && nginx -g 'daemon off;'"
