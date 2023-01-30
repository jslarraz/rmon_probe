#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('rmon_probe.filter')
logger.addHandler(NullHandler())
# --------------------------------------------

import threading
import pcap
import os

class FilterManager():

    ######################
    # Funciones Publicas #
    ######################
    
    def __init__(self, mib):
        print("INIT")
        # Creamos las variables
        self.interfaces = self.get_interfaces()
        self.mib = mib

        self._filters = {}

        # Start filters already in MIB
        self.start()



    def start(self):
        print("START")
        # Cargamos los filtros
        for oid, type, value in self.mib:
            # ChannelEntry with status valid
            if oid.startswith("1.3.6.1.2.1.16.7.2.1.12.") and (value == 1):
                channel_index = int(oid.split(".")[-1])
                self.add(channel_index)


    def add(self, channel_index):
        print("ADD")
        channelMatches = self.mib.get("1.3.6.1.2.1.16.7.2.1.9." + str(channel_index))
        filter, interface = self.genera_filtro(channel_index)
        f = Filter(filter, interface, channelMatches)
        f.start()
        self._filters[channel_index] = f

    def delete(self, channel_index):
        self._filters[channel_index].stop.set()
        del(self._filters[channel_index])



    def shutdown(self):
        for i in self._filters.keys():
            self._filters[i].stop.set()

    def get_interfaces(self):
        interfaces = {}
        for interface in os.listdir("/sys/class/net"):
            # Prevent bonding_masters to generate an exception
            if os.path.isdir("/sys/class/net/" + str(interface)) and os.path.exists("/sys/class/net/" + str(interface) + "/ifindex"):
                fd = open("/sys/class/net/" + str(interface) + "/ifindex")
                try:
                    index = str(int(fd.readline()))
                except:
                    continue
                interfaces[index] = interface
                fd.close()
        return interfaces


    def genera_filtro(self, channel_index):
        logger.debug("GENERA FILTRO")

        interface = None
        filtro = ""

        channelIfIndex = self.mib.get("1.3.6.1.2.1.16.7.2.1.2." + str(channel_index))['value']
        channelAcceptType = self.mib.get("1.3.6.1.2.1.16.7.2.1.3." + str(channel_index))['value']
        channelMatches = self.mib.get("1.3.6.1.2.1.16.7.2.1.9." + str(channel_index))['value']
        if None in [channelIfIndex, channelAcceptType, channelMatches]:
            raise # TODO

        try:
            interface = self.interfaces[str(channelIfIndex)]
        except:
            print("Error to obtain interface")
            raise # TODO

        # Get list of filter indexses
        indexes = []
        for oid, type, value in self.mib:
            if oid.startswith("1.3.6.1.2.1.16.7.1.1.2.") and (value == channel_index):
                filter_index = int(oid.split(".")[-1])
                if self.mib.get("1.3.6.1.2.1.16.7.1.1.11." + str(filter_index))['value'] == 1:
                    indexes.append(filter_index)

        if channelAcceptType == 1:

            for i in range(len(indexes)):
                filter_index = indexes[i]

                filterIndex = self.mib.get("1.3.6.1.2.1.16.7.1.1.1." + str(filter_index))['value']
                filterPktDataOffset = self.mib.get("1.3.6.1.2.1.16.7.1.1.3." + str(filter_index))['value']
                filterPktData= self.mib.get("1.3.6.1.2.1.16.7.1.1.4." + str(filter_index))['value']
                filterPktDataMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.5." + str(filter_index))['value']
                filterPktDataNotMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.6." + str(filter_index))['value']
                filterPktStatus = self.mib.get("1.3.6.1.2.1.16.7.1.1.7." + str(filter_index))['value']
                filterPktStatusMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.8." + str(filter_index))['value']
                filterPktStatusNotMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.9." + str(filter_index))['value']

                filtro = filtro + "("

                for j in range(len(filterPktDataMask)):
                    data = int(ord(filterPktData[j]))
                    mask = int(ord(filterPktDataMask[j]))
                    notMask = int(ord(filterPktDataNotMask[j]))
                    resultado = (data & ~notMask) | (~data & notMask)

                    filtro = filtro + "((ether[" + str(int(filterPktDataOffset) + j ) + "] & " + str(mask) + ") == " + str(resultado) + ")"
                    if j != len(filterPktDataMask)-1:
                        filtro = filtro + " and "

                if i != len(indexes)-1:
                    filtro = filtro + ") or "

            filtro = filtro + ")"

        elif channelAcceptType == 2:

            for i in range(len(indexes)):
                filter_index = indexes[i]

                filterIndex = self.mib.get("1.3.6.1.2.1.16.7.1.1.1." + str(filter_index))['value']
                filterPktDataOffset = self.mib.get("1.3.6.1.2.1.16.7.1.1.3." + str(filter_index))['value']
                filterPktData= self.mib.get("1.3.6.1.2.1.16.7.1.1.4." + str(filter_index))['value']
                filterPktDataMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.5." + str(filter_index))['value']
                filterPktDataNotMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.6." + str(filter_index))['value']
                filterPktStatus = self.mib.get("1.3.6.1.2.1.16.7.1.1.7." + str(filter_index))['value']
                filterPktStatusMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.8." + str(filter_index))['value']
                filterPktStatusNotMask = self.mib.get("1.3.6.1.2.1.16.7.1.1.9." + str(filter_index))['value']

                filtro = filtro + "("

                for j in range(len(filterPktDataMask)):
                    data = int(ord(filterPktData[j]))
                    mask = int(ord(filterPktDataMask[j]))
                    notMask = int(ord(filterPktDataNotMask[j]))
                    resultado = (data & ~notMask) | (~data & notMask)

                    filtro = filtro + "((ether[" + str(int(filterPktDataOffset) + j ) + "] & " + str(mask) + ") != " + str(resultado) + ")"
                    if j != len(filterPktDataMask)-1:
                        filtro = filtro + " or "

                if i != len(indexes)-1:
                    filtro = filtro + ") and "

            filtro = filtro + ")"

        else:
            print("channelAcceptType no valido")
            raise # TODO

        return filtro, interface



class Filter(threading.Thread):

    def __init__(self, filter, interface, matches):
        threading.Thread.__init__(self)
        print("INIT FILTER: " + filter + " on interface: " + interface)
        self.stop = threading.Event()

        self.filter = filter
        self.interface = interface
        self.matches = matches

    def callback(self, self_pc, hdr, data):
        self.matches['value'] += 1

    def run(self):
        pc = pcap.pcapObject()
        pc.open_live(self.interface, 1, True, 1000)
        pc.setfilter(self.filter, True, 0)
        pc.loop(-1, self.callback)
