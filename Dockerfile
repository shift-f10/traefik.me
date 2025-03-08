FROM alpine:latest

# Install PowerDNS, Python 3, and dependencies
RUN apk add --no-cache pdns pdns-backend-pipe python3 py3-pip

# Ensure Python 3 is the default
RUN ln -sf /usr/bin/python3 /usr/bin/python

# Set working directory
WORKDIR /usr/local/bin

# Copy backend script and configuration files
COPY nipio/backend.py .
COPY nipio/backend.conf .
COPY pdns/pdns.conf /etc/pdns/pdns.conf

# Ensure backend script is executable
RUN chmod +x backend.py

EXPOSE 53/tcp 53/udp

# Start PowerDNS server
CMD ["/usr/sbin/pdns_server", "--daemon=no", "--disable-syslog", "--write-pid=no"]
