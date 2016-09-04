import asyncio
import re
from dateutil import parser as timeparser

INTF_REMOVE_RE = re.compile(r'(?P<intf>\w+): removing interface')
ROUTE_ADD_RE = re.compile(r'(?P<intf>\w+): adding default route ' +\
        r'(?P<route>.*)')

SYSLOG_MESSAGE_RE = re.compile(r'<(?P<facility>\d+)>' +\
        r'(?P<date>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+' +\
        r'(?P<host>\w+)\s+(?P<prog>[^\[:]+)(\[(?P<pid>\d+)\])?:\s+' +\
        r'(?P<msg>.*)')

class SysLogHandler(asyncio.DatagramProtocol):
    """ SOCK_DGRAM protocol """

    def connection_made(self, transport):
        for intf in self.runner.data:
            self.runner.loop.create_task(self.runner.restart_interface(intf))


    def datagram_received(self, data, addr):
        """ received data from syslog """
        message = data.decode()
        sysmatch = SYSLOG_MESSAGE_RE.match(message)
        if sysmatch is None:
            self.log.error('Cannot parse syslog with regex: ' + message)
            return

        runner = self.runner

        match = ROUTE_ADD_RE.match(sysmatch.group('msg'))
        if match is not None:
            timestamp = timeparser.parse(sysmatch.group('date'))

            runner.loop.create_task(runner.network_added(match.group('intf'),
                    match.group('route'), timestamp))
            return

        match = INTF_REMOVE_RE.match(sysmatch.group('msg'))
        if match is not None:
            runner.loop.create_task(runner.network_removed(match.group('intf')))


    def error_received(self, exc):
        """ socket error handler """
        self.log.error(str(exc))
