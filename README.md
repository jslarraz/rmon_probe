# RMON probe
RMON probe implementation (rfc 2819) using python and libpcap. Only the filter group is implemented at this moment. This project is a redesign of the original [rmon_probe](https://github.com/jslarraz/rmon_probe_old) that I developed during my [final year project](https://zaguan.unizar.es/record/31543?ln=en).

This redesign involves a major change in the probe architecture, so that the Filter group and its functionality is implemented as an [AgentX](https://datatracker.ietf.org/doc/html/rfc2741) using the [pyagentx2](https://github.com/jslarraz/pyagentx2) library.


## Getting started

The easiest way to get started is to use this probe as a standalone docker container. You can do this simply by running 
the following command.

```
docker run -p 161:161/udp --net=host --name rmon_probe jslarraz/rmon_probe:standalone
```

This docker container is based on [this](https://hub.docker.com/r/jslarraz/netsnmp) docker image. You can configure the NetSNMP agent according to its documentation.

## Better alternatives

You can also run the probe with as a set of containers using docker compose, which is a more reliable alternative. There
are two ways to manage secrets between container, using docker secrets or environment variables. 

### Create secrets

#### Docker secrets

This is the preferred way to manage your secrets within the docker environment. You should start creating the required 
docker secrets using your docker cli. 

```
printf "my_root_pass" | docker secret create rmon-db-root -
printf "my_db_name" | docker secret create rmon-db-name -
printf "my_user" | docker secret create rmon-db-user -
printf "my_pass" | docker secret create rmon-db-pass -
```

#### Environment variables

This method is not current supported in this version but is planned to be supported for development environments in the 
future. 

### Run the docker-compose

## Workaround for windows containers

If you want to run it on Docker for windows you will need the following workaround. The idea is to allow the rmon_probe
container to capture packages on the host using  tshark (which is distributed as part of wireshark) over ssh, and the 
use tcpreplay to send them over the interface of the docker container. This could be achieved by running the following 
command on the rmon_probe container. 

```
ssh win_user@win_host tshark -w - 'not port 22' | tcpreplay -i eth0 -
```

You need to increase the MTU of the docker network. It can be done by including the following option in the docker 
daemon config file.

```
"mtu": 9000"
```

## References

Code in this repository was initially developed as part of my Final undergraduate project, and full details about the 
system architecture, implementation decisions and performance test is available at project report (only Spanish).

https://zaguan.unizar.es/record/31543?ln=en



##Run things without root

apt-get install libcap2-bin
sudo setcap cap_net_bind_service,cap_net_raw,cap_net_admin=eip /usr/bin/python2.7
