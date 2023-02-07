#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('pyagentx2.mib_MySQL')
logger.addHandler(NullHandler())
# --------------------------------------------


import os
import MySQLdb
from pyagentx2.mib import MIB
import signal

MAX_OID_CHARACTERS = 50

class MIB_MySQL(MIB):
    def __init__(self, maria_host='localhost', mariadb_user='rmon', mariadb_pass='rmon', mariadb_database='rmon', table_name='mib', sync_freq=10, auto_sync=None):
        super(MIB_MySQL, self).__init__()

        # Connect to the database
        HOST = os.environ.get('MARIADB_HOST', maria_host)
        USER = os.environ.get('MARIADB_USER', mariadb_user)
        PASS = os.environ.get('MARIADB_PASS', mariadb_pass)
        DATABASE = os.environ.get('MARIADB_DATABASE', mariadb_database)

        self.table_name = table_name

        connection = MySQLdb.connect(host=HOST, user=USER, passwd=PASS)
        connection.autocommit(True)
        self.cursor = connection.cursor()

        # Check if the database has been properly init.
        try:
            self.cursor.execute("SHOW DATABASES;")
            databases = self.cursor.fetchall()
        except:
            logger.error("Mysql is not running. Shutting down...")
            exit(-1)

        if not (DATABASE in str(databases)):
            logger.info("Database " + DATABASE + " not found in the database server " + HOST)
            try:
                self.cursor.execute("CREATE DATABASE " + DATABASE + ";")
            except:
                logger.error("Error while creating database " + DATABASE)

        try:
            self.cursor.execute("USE " + DATABASE + ";")
            self.cursor.execute("SHOW TABLES;")
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

    def set(self, oid, type, value):
        super(MIB_MySQL, self).set(oid, type, value)
        self.set_MySQL(oid, type, value)

    def set_MySQL(self, oid, type, value):
        try:
            self.cursor.execute('INSERT INTO ' + self.table_name + ' (oid, type, value) VALUES ("%(oid)s", %(type)s, "%(value)s") ON DUPLICATE KEY UPDATE type=%(type)s, value="%(value)s";' % {"oid": oid, "type": type, "value": value})
        except:
            print("error")
            logger.error("Error creating/updating entry oid " + oid + " with type " + str(type) + " and value " + str(value))

    def delete_oid(self, oid):
        super(MIB_MySQL, self).delete_oid(oid)
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
                    self.set_MySQL(oid, type, value)
