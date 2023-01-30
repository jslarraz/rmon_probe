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

import MySQLdb
# from scapy.all import *
from multiprocessing import Process, Value, Array
import pcap

class Filter():

    ######################
    # Funciones Publicas #
    ######################
    
    def __init__(self, mib, interfaces=None):
        # Creamos las variables
        self.interfaces = interfaces
        self.mib = mib




    def start(self):
        # Cargamos los filtros
        db_rmon=MySQLdb.connect(host=self.BBDD.ADDR,user=self.BBDD.USER,passwd=self.BBDD.PASS, db="rmon")
        db_rmon.autocommit(True)
        cursor = db_rmon.cursor()

        cursor.execute("SELECT channelIndex FROM td_channelEntry WHERE channelStatus = \'1\'" )
        result = cursor.fetchall()
        if str(result) != "None":
            for canal in result:
                # Comprobamos que hay sitio en la memoria compartida
                self.ind = self.busca_memoria()
                if self.ind != None:
                    status, match, interfaz, filtro = self.genera_filtro(str(canal[0]))
                    if status == 1:
                        self.indices[self.ind] = canal[0]
                        self.matches[self.ind] = match
                        self.process[self.ind] = Process(target=self.captura, args=(interfaz, filtro))
                        self.process[self.ind].start()

                    else:
                        print("Formato de filtro erroneo")

                else:
                    print("No hay espacio en memoria para el filtro")

        else:
            print("No hay ningun filtro declarado")





    def add(self, index):
        self.ind = self.busca_memoria()
        if self.ind != None:
            status, match, interfaz, filtro = self.genera_filtro(str(index))
            if status == 1:
                self.indices[self.ind] = int(index)
                self.matches[self.ind] = match
                self.process[self.ind] = Process(target=self.captura, args=(interfaz, filtro))
                self.process[self.ind].start()
                print(filtro)

            else:
                print("Formato de filtro erroneo")

        else:
            print("No hay espacio en memoria para el filtro")


    def delete(self, index):

        ind = None
        for i in range(len(self.indices)):
            if self.indices[i] == int(index):
                ind = i

                if ind != None:
                    self.indices[ind] = 0
                    self.matches[ind] = 0
                    self.process[ind].terminate()

                else:
                    print("El filto no existia")


    def kill(self):
        for i in range(len(self.indices)):
            if self.indices[i] != 0:
                self.process[i].terminate()


    def update(self):
        db_rmon=MySQLdb.connect(host=self.BBDD.ADDR,user=self.BBDD.USER,passwd=self.BBDD.PASS, db="rmon")
        db_rmon.autocommit(True)
        cursor = db_rmon.cursor()

        for i in range(len(self.indices)):
            if self.indices[i] != 0:
                cursor.execute("UPDATE td_channelEntry SET channelMatches = " + str(self.matches[i]) + " WHERE channelIndex = %s", (str(self.indices[i]),) )
                #print str(self.indices[i]) + ": " + str(self.matches[i])



    ######################
    # Funciones Privadas #
    ######################


    def genera_filtro(self, channel_index):
        logger.debug("GENERA FILTRO")

        interface = None
        filtro = ""

        channelIfIndex = self.mib.get("1.3.6.1.2.1.16.7.2.1.2." + str(channel_index))['value']
        channelAcceptType = self.mib.get("1.3.6.1.2.1.16.7.2.1.3." + str(channel_index))['value']
        channelMatches = self.mib.get("1.3.6.1.2.1.16.7.2.1.9." + str(channel_index))['value']
        if None in [channelIfIndex, channelAcceptType, channelMatches]:
            raise # TODO

        # try:
        #     interfaz = self.interfaces[str(channelIfIndex)]
        #     # interfaz = subprocess.check_output(["snmpget", "-v", "1", "-c", "public", "localhost:162", "1.3.6.1.2.1.2.2.1.2." + str(channelIfIndex)])
        #     # interfaz = interfaz.split("\"")
        #     # interfaz = interfaz[1]
        # except:
        #     print("Error al conseguir el interfaz")
        #     raise # TODO

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



#    def callback(self, pkt):
    def callback(self, self_pc, hdr, data):
        self.matches[self.ind] += 1
        
    def captura(self, interfaz, filtro):  
#        sniff(iface=interfaz, filter=filtro, prn=self.callback)
        pc = pcap.pcapObject()
        pc.open_live(interfaz, 1, True, 1000)
        pc.setfilter(filtro, True, 0)
        pc.loop(-1, self.callback)
