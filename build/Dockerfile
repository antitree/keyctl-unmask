FROM golang
WORKDIR /go/src/keyctl-unmask/
COPY go.mod .
RUN go mod download
ADD ./cmd/keyctl-unmask .
RUN go build . 

FROM ubuntu
RUN apt update && apt install keyutils jq curl netcat net-tools lsof linux-tools-generic -y --no-install-recommends && apt-get clean && rm -rf  /var/log/*log /var/lib/apt/lists/* /var/log/apt/* /var/lib/dpkg/*-old /var/cache/debconf/*-old
COPY --from=0 /go/src/keyctl-unmask/keyctl-unmask /bin/keyctl-unmask
CMD ["/bin/keyctl-unmask"] 