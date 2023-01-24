#!/usr/bin/env python
# -*- coding: utf-8 -*-

'''

snmpwalk -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleScalars
snmptable -v 2c -c public -Ci localhost NET-SNMP-EXAMPLES-MIB::netSnmpIETFWGTable

Try snmpset:
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleInteger.0 i 10
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleInteger.0 i 200
snmpset -v 2c -c public localhost NET-SNMP-EXAMPLES-MIB::netSnmpExampleString.0 s "Test"

'''


import pyagentx2
from rmon_probe.rmonTableSetHandler import RmonTableSetHandler

class FilterTableUpdater(pyagentx2.Updater):

    def update(self, mib):
        # implement netSnmpIETFWGTable from NET-SNMP-EXAMPLES-MIB.txt
        # Number of entries in table is random to show that MIB is reset
        # on every update
        # mib.set_INTEGER('1.3.6.1.2.1.16.7.1.1.1.11.100', 100)
        pass

class FilterTableSetHandler(RmonTableSetHandler):

    def valid(self, oid, type, value, mib):
        print("VALID FILTER CALLED: %s = %s" % (oid, value))


# class ChannelTableUpdater(pyagentx2.Updater):
#
#     def update(self, mib):
#         # implement netSnmpIETFWGTable from NET-SNMP-EXAMPLES-MIB.txt
#         # Number of entries in table is random to show that MIB is reset
#         # on every update
#         mib.set_INTEGER('1.3.6.1.2.1.16.7.2.1.1.11.200', 200)
#         print(mib.get_oids())
#
# class ChannelTableSetHandler(pyagentx2.SetHandler):
#
#     def test(self, oid, type, value, mib):
#         pass
#         # if int(data) > 100:
#         #     raise pyagentx2.SetHandlerError()
#
#     def commit(self, oid, type, value, mib):
#         print("COMMIT CHANNEL CALLED: %s = %s" % (oid, value))
#         mib.set(oid, type, value)


class MyAgent(pyagentx2.Agent):

    def setup(self):

        self.register('1.3.6.1.2.1.16.7.1', FilterTableUpdater)
        self.register_set('1.3.6.1.2.1.16.7.1', RmonTableSetHandler)

        # self.register('1.3.6.1.2.1.16.7.2', ChannelTableUpdater)
        # self.register_set('1.3.6.1.2.1.16.7.2', ChannelTableSetHandler)

def main():
    pyagentx2.setup_logging(debug=True)
    try:
        a = MyAgent()
        a.start()
    except Exception as e:
        print("Unhandled exception:", e)
        a.stop()
    except KeyboardInterrupt:
        a.stop()

if __name__=="__main__":
    main()

