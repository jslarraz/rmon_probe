#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('pyagentx2.mib_SQLite')
logger.addHandler(NullHandler())
# --------------------------------------------


import os
import struct
import sqlite3
from pyagentx2.mib import MIB
import signal

MAX_OID_CHARACTERS = 50

# Serialized. https://docs.python.org/3/library/sqlite3.html#sqlite3.threadsafety
sqlite3.threadsafety = 3

class MIB_SQLite(MIB):
    def __init__(self, database='rmon', table='mib', sync_freq=10, auto_sync=None):
        super(MIB_SQLite, self).__init__()

        # Connect to the database
        DATABASE = os.environ.get('MARIADB_DATABASE', database)

        self.table_name = table

        self.connection = sqlite3.connect(DATABASE, check_same_thread=False)
        self.cursor = self.connection.cursor()

        try:
            self.cursor.execute("SELECT name FROM sqlite_master;")
            tables = self.cursor.fetchall()
        except:
            logger.error("Database can not be selected properly")
            exit(-1)

        if not (self.table_name in str(tables)):
            logger.info("Table " + self.table_name + " not found in the database " + DATABASE)
            try:
                self.cursor.execute("CREATE TABLE " + self.table_name + " ( oid VARCHAR(" + str(MAX_OID_CHARACTERS) + ") PRIMARY KEY, type INT, value TEXT);")
            except:
                logger.error("Error while creating table " + self.table_name)
                exit(-1)

        # Load objects from MySQL database
        self.cursor.execute("SELECT * FROM " + self.table_name + ";")
        result = self.cursor.fetchall()
        for oid, type, value in result:
            if (type == 2) or (type == 65):   # TODO add support for more data types
                value = int(value)
            self.data[oid] = {'name': oid, 'type': type, 'value': value}
        self.data_idx = sorted(self.data.keys(), key=lambda k: tuple(int(part) for part in k.split('.')))

        # Set sync function
        if sync_freq is not None:
            self.auto_sync = auto_sync
            self.sync_freq = sync_freq
            signal.signal(signal.SIGALRM, self.sync_timer)
            signal.alarm(self.sync_freq)

    def set(self, oid, type_, value):
        super(MIB_SQLite, self).set(oid, type_, value)
        self.set_SQLite(oid, type_, value)

    def set_SQLite(self, oid, type_, value):
        try:
            if type_ == 4:
                aux = ""
                for c in value:
                    aux += str(struct.unpack('!B', c.encode('charmap'))[0]) + ","
                value = "char(" + aux[0:-1] + ")"
                self.cursor.execute('INSERT INTO ' + self.table_name + ' (oid, type, value) VALUES ("%(oid)s", %(type)s, %(value)s) ON CONFLICT(oid) DO UPDATE SET type=%(type)s, value=%(value)s;' % {"oid": oid, "type": type_, "value": value})
            else:
                self.cursor.execute('INSERT INTO ' + self.table_name + ' (oid, type, value) VALUES ("%(oid)s", %(type)s, "%(value)s") ON CONFLICT(oid) DO UPDATE SET type=%(type)s, value="%(value)s";' % {"oid": oid, "type": type_, "value": value})
            self.connection.commit()
        except Exception,e:
            print(str(e))
            logger.error("Error creating/updating entry oid " + oid + " with type " + str(type_) + " and value " + str(value))

    def delete_oid(self, oid):
        super(MIB_SQLite, self).delete_oid(oid)
        try:
            self.cursor.execute('DELETE FROM ' + self.table_name + ' WHERE oid = "' + oid + '";')
        except:
            logger.error("Error deleting entry with oid " + oid)

    def sync_timer(self, signum, frame):
        self.sync()
        signal.alarm(self.sync_freq)

    def sync(self):

        if self.auto_sync is not None:
            for oid, type, value in self:
                if oid.startswith(self.auto_sync):
                    self.set_SQLite(oid, type, value)
