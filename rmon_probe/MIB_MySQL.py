#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('rmon_probe.MIB_MySQL')
logger.addHandler(NullHandler())
# --------------------------------------------

import re
import os
import MySQLdb
from pyagentx2.mib import MIB



class MIB_MYSQL(MIB):
    def __init__(self, db_file):
        super(MIB_MYSQL, self).__init__()

        # Connect to the database
        HOST = os.environ.get('MARIADB_HOST', 'db')
        USER = os.environ.get('MARIADB_USER', 'rmon')
        PASS = os.environ.get('MARIADB_PASS', 'rmon')
        DATABASE = os.environ.get('MARIADB_DATABASE', 'rmon')

        connection = MySQLdb.connect(host=HOST, user=USER, passwd=PASS)
        cursor = connection.cursor()

        # Check if the database has been properly init.
        try:

            cursor.execute("SHOW DATABASES;")
            databases = cursor.fetchall()

            if not (DATABASE in str(databases)):
                logger.warning("database " + DATABASE + " not found in the database server " + HOST)
                statement = ""
                for line in open(db_file):
                    if re.match(r'--', line):
                        continue
                    if not re.search(r'[^-;]+;', line):
                        statement = statement + line
                    else:
                        statement = statement + line
                        try:
                            cursor.execute(statement)
                        except:
                            logger.warning("incorrect sql statement while creating database instance")
                        statement = ""

        except:
            logger.error("Mysql is not running. Shutting down...")
            exit(-1)

        # Load objects from MySQL database

    def set(self, oid, type, value):
        super().set(oid, type, value)

    def delete_oid(self, oid):
        super().delete_oid(oid)

