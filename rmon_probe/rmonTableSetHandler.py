#!/usr/bin/env python
# -*- coding: utf-8 -*-

# --------------------------------------------
import logging
class NullHandler(logging.Handler):
    def emit(self, record):
        pass
logger = logging.getLogger('rmon_probe.rmonTableSetHandler')
logger.addHandler(NullHandler())
# --------------------------------------------


import json

from pyagentx2 import SetHandler, GenErrException, NoAccessException, WrongTypeException, WrongLengthException, WrongEncodingException, WrongValueException, NoCreationException, InconsistentValueException, ResourceUnavailableException, NotWritableException, InconsistentNameException


class RmonTableSetHandler(SetHandler):

    def __init__(self, schema_file):
        SetHandler.__init__(self)
        schema = open(schema_file).read()
        try:
            self.schema = json.loads(schema)
            self.schema_idx = sorted(self.schema.keys(), key=lambda k: tuple(int(part) for part in k.split('.')))
            self.index_oid = self.schema_idx[0]
            self.status_oid =  self.schema_idx[-1]
        except:
            logger.error("Error while loading RMON table schema.")


    def test(self, oid, type, value, mib):

        # If the oid is already in the mib, it should be valid, I have check it during creation
        try:
            aux = oid.split(".")
            row_index = int(aux[-1])
            oid_prefix = '.'.join(aux[:-1])
        except:
            raise GenErrException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (2)
        # If it is not a table element
        if not (oid_prefix in self.schema_idx):
            raise NotWritableException()

        # Get schema of the oid to check object constrains
        schema = self.schema[oid_prefix]

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (3)
        if ('syntax-code' in schema.keys()) and (type != schema['syntax-code']):
            raise WrongTypeException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (4)
        if ('min-length' in schema.keys()) and (len(value) < schema['min-length']):
            raise WrongLengthException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (4)
        if ('max-length' in schema.keys()) and (len(value) > schema['max-length']):
            raise WrongLengthException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (5)
        # We are not considering wrongEncoding in this agent

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (6)
        if ('min-value' in schema.keys()) and (value < schema['min-value']):
            raise WrongValueException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (6)
        if ('max-value' in schema.keys()) and (value > schema['max-value']):
            raise WrongValueException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (7)
        # All OIDs that pass previous tests can be created

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (8)
        # Does not exist and cannot be created under current conditions (is not an entry status)
        if (not mib.has_oid(oid)) and (oid_prefix != self.status_oid):
            raise InconsistentNameException()

        # Get entry status
        status = mib.get(self.status_oid + "." + str(row_index))

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (9)
        # exists but cannot be modified no matter which value (it is not the entryStatus and its entryStatus is not underCreation)
        if (mib.has_oid(oid)) and (oid_prefix != self.status_oid) and (status['value'] != 3):
            raise NotWritableException()

        # It is read only
        if ('access-code' in schema.keys()) and (schema['access-code'] < 2):
            raise NotWritableException()

        # https://www.rfc-editor.org/rfc/rfc1905#section-4.2.5 (10)
        if (oid_prefix == self.status_oid) and (not mib.has_oid(oid)) and ((value != 2) and (value != 4)):
                raise InconsistentValueException()

        if (oid_prefix == self.status_oid) and (mib.has_oid(oid)) and (value == 2):
            raise InconsistentValueException()

        # Assess we have enough resources to allocate the filter
        # resourceUnavailable



    def commit(self, oid, type, value, mib):

        # Get row index and oid prefix
        try:
            aux = oid.split(".")
            row_index = int(aux[-1])
            oid_prefix = '.'.join(aux[:-1])
        except:
            raise GenErrException() # Commit Failed

        # For entryStatus
        if oid_prefix == self.status_oid:

            # If exists
            if mib.has_oid(oid):
                # Create filter
                if value == 1:
                    self.valid(oid, type, value, mib)
                    mib.set(oid, type, value)

                # Delete entry
                elif value == 4:
                    for prefix in self.schema_idx:
                        oid = prefix + '.' + str(row_index)
                        mib.delete_oid(oid)

            else:
                if value == 2:
                    for prefix in self.schema_idx:
                        oid = prefix + '.' + str(row_index)
                        type = self.schema[prefix]['syntax-code']
                        if (type == 2) or (type == 65):  # TODO add support for more data types initialization
                            value = 0
                        elif type == 4:
                            value = ''
                        else:
                            logger.error("Unrecognised data type. Sipping " + prefix)
                            continue

                        # Special cases for index and entryStatus
                        if prefix == self.index_oid:
                            value = row_index
                        elif prefix == self.status_oid:
                            value = 3  # Under creation

                        mib.set(oid, type, value)

        # Commit
        else:
            mib.set(oid, type, value)






    def valid(self, oid, type, value, mib):
        print("CREATING NEW FILTER")
        pass