import asyncio
import re
from dateutil import parser as timeparser

INTF_REMOVE_RE = re.compile(r'(?P<intf>\w+): removing interface')
DHCPCD_ADD_RE = re.compile(r'(?P<intf>\w+): (adding|changing) default route ' +\
        r'(?P<route>.*)')
WPA_ADD_RE = re.compile(r'interface (?P<intf>\w+) CONNECTED')
KERNEL_ADD_RE = re.compile(r'(?P<intf>\w+): link becomes ready')

SYSLOG_MESSAGE_RE = re.compile(r'<(?P<facility>\d+)>' +\
        r'(?P<date>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+' +\
        r'(?P<host>\w+)\s+(?P<prog>[^\[:]+)(\[(?P<pid>\d+)\])?:\s+' +\
        r'(?P<msg>.*)')

class SysLogHandler(asyncio.DatagramProtocol):
    """ SOCK_DGRAM protocol """

    def connection_made(self, transport):
        for interface in self.runner.data:
            data = self.runner.data[interface]
            if not data['active']:
                continue
            self.runner.loop.create_task(self.runner.restart_interface(interface))
            self.runner.loop.create_task(self.runner.test_connection(interface))


    def datagram_received(self, data, addr):
        """ received data from syslog """
        message = data.decode()
        sysmatch = SYSLOG_MESSAGE_RE.match(message)
        if sysmatch is None:
            self.log.error('Cannot parse syslog with regex: ' + message)
            return

        runner = self.runner

        match = DHCPCD_ADD_RE.match(sysmatch.group('msg'))
        if match is not None:
            timestamp = timeparser.parse(sysmatch.group('date'))

            runner.loop.create_task(runner.network_added(match.group('intf'),
                    match.group('route'), timestamp))
            return

        match = INTF_REMOVE_RE.match(sysmatch.group('msg'))
        if match is not None:
            runner.loop.create_task(runner.network_removed(match.group('intf')))
            return

        match = WPA_ADD_RE.match(sysmatch.group('msg'))
        if match is None:
            match = KERNEL_ADD_RE.match(sysmatch.group('msg'))
        if match is not None:
            # probably interface with static ip was connected
            timestamp = timeparser.parse(sysmatch.group('date'))

            runner.loop.create_task(runner.network_added(match.group('intf'),
                    None, timestamp))
            return


    def error_received(self, exc):
        """ socket error handler """
        self.log.error(str(exc))
