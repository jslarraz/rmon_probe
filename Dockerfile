# Choose base image
FROM jslarraz/netsnmp:latest

# Update repository
RUN apt-get update

# Install apt-utils
RUN apt-get -y install apt-utils

# Install python (v2.7)
RUN apt-get -y install python
RUN apt-get -y install python-pip

# Install MySQL client
RUN apt-get -y install mariadb-client
RUN apt-get -y install python-mysqldb

# Install libpcap
RUN apt-get -y install libpcap-dev
RUN apt-get -y install python-libpcap

# Install python requirements
ADD requirements.txt /tmp
RUN pip install -r /tmp/requirements.txt

# Copy project files to working directory
WORKDIR /tmp
ADD . .

EXPOSE 161/udp
CMD /tmp/start_snmpd.sh && python rmon_agent.py




