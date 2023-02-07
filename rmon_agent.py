#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pyagentx2
from rmon_probe.rmonTableSetHandler import RmonTableSetHandler
from rmon_probe.mib_MySQL import MIB_MySQL
from rmon_probe.mib_SQLite import MIB_SQLite
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
            print("error create filter")
            raise

    def invalid(self, index):
        print("INVALID FILTER CALLED: %s" % (index))
        try:
            self.filter_manager.delete(index)
        except:
            print("error delete index")
            pass
            # raise

class FilterGroupAgent(pyagentx2.Agent):

    def __init__(self):
        super(FilterGroupAgent, self).__init__()
        self.mib = MIB_SQLite(database='/var/lib/rmon/filter.db', auto_sync='1.3.6.1.2.1.16.7.2.1.9')

    def setup(self):

        self.register('1.3.6.1.2.1.16.7.1')
        self.register_set('1.3.6.1.2.1.16.7.1', RmonTableSetHandler, "rmon_probe/filter_table.json")

        self.register('1.3.6.1.2.1.16.7.2')
        self.register_set('1.3.6.1.2.1.16.7.2', ChannelTableSetHandler, "rmon_probe/channel_table.json", self.mib)

def main():
    pyagentx2.setup_logging(debug=False)
    agent = FilterGroupAgent()
    try:
        agent.start()
    except Exception as e:
        print("Unhandled exception:", e)
        agent.stop()
    except KeyboardInterrupt:
        agent.stop()

if __name__=="__main__":
    main()

