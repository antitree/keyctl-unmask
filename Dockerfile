FROM ubuntu

RUN apt update && apt install keyutils curl netcat net-tools lsof linux-tools-generic -y --no-install-recommends && apt-get clean && rm -rf  /var/log/*log /var/lib/apt/lists/* /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old

COPY keyctl-unmask /bin/keyctl-unmask
