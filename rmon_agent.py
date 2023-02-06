#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""

snmpwalk -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleScalars
snmptable -v 2c -c public -Ci localhost NET-SNMP-EXAMPLES-MIB::netSnmpIETFWGTable

Try snmpset:
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleInteger.0 i 10
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleInteger.0 i 200
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleString.0 s "Test"

"""


import pyagentx2
from rmon_probe.rmonTableSetHandler import RmonTableSetHandler
from rmon_probe.MIB_MySQL import MIB_MYSQL
from rmon_probe.filter import FilterManager


class ChannelTableSetHandler(RmonTableSetHandler):

    def __init__(self, schema_file, mib):
        super(ChannelTableSetHandler, self).__init__(schema_file)
        try:
            self.filter_manager = FilterManager(mib)
        except:
            print("Error while initialization the FilterManager")
        self.mib = mib

    def valid(self, index):
        print("VALID FILTER CALLED: %s" % (index))
        try:
            self.filter_manager.add(index)
        except:
            raise

    def invalid(self, index):
        print("INVALID FILTER CALLED: %s" % (index))
        try:
            self.filter_manager.delete(index)
        except:
            print("error delete index")
            pass
            # raise



class MIB_Filter(MIB_MYSQL):

    def MySQL_sync(self):
        for oid, type, value in self:
            if oid.startswith("1.3.6.1.2.1.16.7.2.1.9."):
                self.cursor.execute(
                    'INSERT INTO ' + self.table_name + ' (oid, type, value) VALUES ("%(oid)s", %(type)s, "%(value)s") ON DUPLICATE KEY UPDATE type=%(type)s, value="%(value)s";' % {
                        "oid": oid, "type": type, "value": value})


class MyAgent(pyagentx2.Agent):

    def __init__(self):
        super(MyAgent, self).__init__()
        self.mib = MIB_Filter()

    def setup(self):

        self.register('1.3.6.1.2.1.16.7.1')
        self.register_set('1.3.6.1.2.1.16.7.1', RmonTableSetHandler, "rmon_probe/filter_table.json")

        self.register('1.3.6.1.2.1.16.7.2')
        self.register_set('1.3.6.1.2.1.16.7.2', ChannelTableSetHandler, "rmon_probe/channel_table.json", self.mib)

def main():
    pyagentx2.setup_logging(debug=False)
    a = MyAgent()
    try:
        a.start()
    except Exception as e:
        print("Unhandled exception:", e)
        a.stop()
    except KeyboardInterrupt:
        a.stop()

if __name__=="__main__":
    main()

