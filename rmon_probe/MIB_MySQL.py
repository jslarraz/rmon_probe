#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('pyagentx2.MIB_MySQL')
logger.addHandler(NullHandler())
# --------------------------------------------


import os
import MySQLdb
from pyagentx2.mib import MIB

MAX_OID_CHARACTERS = 50

class MIB_MYSQL(MIB):
    def __init__(self):
        super(MIB_MYSQL, self).__init__()

        # Connect to the database
        HOST = os.environ.get('MARIADB_HOST', 'db')
        USER = os.environ.get('MARIADB_USER', 'rmon')
        PASS = os.environ.get('MARIADB_PASS', 'rmon')
        DATABASE = os.environ.get('MARIADB_DATABASE', 'rmon')

        self.table_name = "mib"

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
        self.cursor.execute("SELECT * FROM mib;")
        result = self.cursor.fetchall()
        for oid, type, value in result:
            if (type == 2) or (type == 65):   # TODO add support for more data types
                value = int(value)
            self.data[oid] = {'name': oid, 'type': type, 'value': value}
        self.data_idx = sorted(self.data.keys(), key=lambda k: tuple(int(part) for part in k.split('.')))

    def set(self, oid, type, value):
        super(MIB_MYSQL, self).set(oid, type, value)
        try:
            self.cursor.execute('INSERT INTO ' + self.table_name + ' (oid, type, value) VALUES ("%(oid)s", %(type)s, "%(value)s") ON DUPLICATE KEY UPDATE type=%(type)s, value="%(value)s";' % {"oid": oid, "type": type, "value": value})
        except:
            print("error")
            logger.error("Error creating/updating entry oid " + oid + " with type " + str(type) + " and value " + str(value))

    def delete_oid(self, oid):
        super(MIB_MYSQL, self).delete_oid(oid)
        try:
            self.cursor.execute('DELETE FROM ' + self.table_name + ' WHERE oid = "' + oid + '";')
        except:
            logger.error("Error deleting entry with oid " + oid)

