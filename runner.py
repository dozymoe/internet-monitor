import asyncio
import re

from copy import copy
from datetime import datetime, timedelta
from random import shuffle

MULTIPATH_TABLE = 323

ROUTE_DEF_RE = re.compile(r'(?P<network>\d+\.\d+\.\d+\.\d+/\d+).*?' +\
        r'src (?P<ip>\d+\.\d+\.\d+\.\d+).*')

PING_SUCCESS_RE = re.compile(r'(?P<max>\d+) packets transmitted, ' +\
        r'(?P<count>\d+) received')


class Runner(object):
    """ main program """
    data = None
    log = None
    loop = None
    reroute_timestamp = None
    rerouting = False

    def __init__(self, event_loop, config, logger):
        self.data = {}
        for intf in config:
            self.data[intf] = {
                'active': True,
                'connected': False,
                'test_ip': 'google.co.id',
                'has_reconnect_thread': False,
                'weight': 1,
                'local_ip': None,
                'network': None,
                'route': None,
                'test_success_count': 1,
            }
            self.data[intf].update(config[intf])

        self.log = logger
        self.loop = event_loop


    @asyncio.coroutine
    def network_added(self, interface, defroute, log_timestamp):
        self.log.debug('Runner::network %s added.' % interface)
        data = self.data.get(interface)
        if data is None or not data['active']:
            yield from asyncio.sleep(5)
            process = yield from asyncio.create_subprocess_exec(
                    '/bin/ip', 'route', 'del', 'default', defroute)
            yield from process.wait()
            return

        self.log.info('New network connection for %s.' % interface)

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ip', 'route', 'list', 'dev', interface, 'scope', 'link',
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)

        out, err = yield from process.communicate()
        out = out.decode()

        match = ROUTE_DEF_RE.match(out)
        data['network'] = match.group('network')
        data['local_ip'] = match.group('ip')
        data['route'] = '%s dev %s' % (defroute, interface)
        data['connected'] = True

        self.reroute_timestamp = log_timestamp + timedelta(seconds=10)


    @asyncio.coroutine
    def setup_routing(self):
        yield from asyncio.sleep(10)
        if self.reroute_timestamp is None or \
                datetime.now() < self.reroute_timestamp:

            self.loop.create_task(self.setup_routing())
            return

        self.rerouting = True
        self.reroute_timestamp = None
        self.log.debug('Runner:setup_routing')

        multipath_table = str(MULTIPATH_TABLE)

        self.log.debug('Clean routing table.')
        for ii in range(len(self.data)):
            yield from self._purge_route_table(str(200 + ii + 1))
        yield from self._purge_route_table(multipath_table)

        process = yield from asyncio.create_subprocess_exec(
                '/sbin/iptables', '-t', 'nat', '-F')

        yield from process.wait()

        # main table without default gateway
        yield from self.run_until_error('/bin/ip', 'route', 'del', 'default')

        self.log.debug('Create new routing table.')

        for ii, interface in enumerate(self.data):
            data = self.data[interface]

            if not data['active'] or not data['connected']:
                continue

            table_id = str(200 + ii + 1)

            process = yield from asyncio.create_subprocess_exec(
                    '/bin/ip', 'rule', 'add', 'prio', table_id, 'from',
                    data['local_ip'], 'table', table_id)

            yield from process.wait()

            process = yield from asyncio.create_subprocess_exec(
                    '/bin/ip', 'route', 'add', 'default',
                    'src', data['local_ip'], 'proto', 'static', 'table',
                    table_id, *data['route'].split(' '))

            yield from process.wait()

            process = yield from asyncio.create_subprocess_exec(
                    '/bin/ip', 'route', 'append', 'prohibit', 'default',
                    'metric', '1', 'proto', 'static', 'table', table_id)

            yield from process.wait()

            process = yield from asyncio.create_subprocess_exec(
                    '/sbin/iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o',
                    interface, '-j', 'MASQUERADE')

            yield from process.wait()

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ip', 'rule', 'del', 'prio', '32765')

        yield from process.wait()

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ip', 'rule', 'add', 'prio', '32765', 'table', 'main')

        yield from process.wait()

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ip', 'rule', 'del', 'prio', '32766')

        yield from process.wait()

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ip', 'rule', 'add', 'prio', '32766', 'table',
                multipath_table)

        yield from process.wait()

        load_balancing = ['/bin/ip', 'route', 'add', 'default', 'table',
                multipath_table, 'proto', 'static']

        hops = [x for x in self.data if self.data[x]['active'] and \
                self.data[x]['connected']]
        shuffle(hops)

        if len(hops) == 0:
            load_balancing = None
        elif len(hops) == 1:
            load_balancing.extend(self.data[hops[0]]['route'].split(' '))
        else:
            for intf in hops:
                load_balancing.append('nexthop')
                load_balancing.extend(self.data[intf]['route'].split(' '))
                load_balancing.append('weight')
                load_balancing.append(str(self.data[intf]['weight']))

        if load_balancing:
            process = yield from asyncio.create_subprocess_exec(*load_balancing)
            yield from process.wait()

        process = yield from asyncio.create_subprocess_exec('/bin/ip',
                'route', 'flush', 'cache')

        yield from process.wait()

        self.rerouting = False
        self.loop.create_task(self.setup_routing())


    @asyncio.coroutine
    def network_removed(self, interface):
        if interface not in self.data:
            return
        self.log.debug('Runner::network %s removed.' % interface)

        data = self.data[interface]
        data['connected'] = False
        data['local_ip'] = None
        data['network'] = None
        data['route'] = None
        self.log.info('Lost network connection for %s.' % interface)

        self.reroute_timestamp = datetime.now()


    @asyncio.coroutine
    def restart_interface(self, interface):
        yield from asyncio.sleep(5)
        self.log.debug('Runner::restart %s interface.' % interface)
        process = yield from asyncio.create_subprocess_exec(
                '/etc/init.d/net.%s' % interface, 'restart')

        yield from process.wait()


    @asyncio.coroutine
    def test_connection(self, interface):
        data = self.data[interface]
        yield from asyncio.sleep(60 * data['test_success_count'])
        self.log.debug('Runner:test %s connection.' % interface)

        if self.rerouting:
            self.loop.create_task(self.test_connection(interface))
            return

        process = yield from asyncio.create_subprocess_exec(
                '/bin/ping', '-qn', '-I', interface, '-c', '2', '-W', '10',
                data['test_ip'], stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)

        out, err = yield from process.communicate()
        out = out.decode()
        match = PING_SUCCESS_RE.search(out)
        success = len(err) == 0 and match is not None and \
                match.group('max') and match.group('count')

        if not success:
            data['test_success_count'] = 1
            self.log.error('Ping failed: %s.' % out)
            self.loop.create_task(self.restart_interface(interface))
        elif data['test_success_count'] < 15:
            data['test_success_count'] += 1

        self.loop.create_task(self.test_connection(interface))


    @asyncio.coroutine
    def run_until_error(self, *args):
        max_retry = 5
        while max_retry:
            process = yield from asyncio.create_subprocess_exec(*args)
            ret = yield from process.wait()
            if ret:
                break
            max_retry -= 1


    @asyncio.coroutine
    def _purge_route_table(self, table_id):
        yield from self.run_until_error('/bin/ip', 'rule', 'del', 'table',
                table_id)

        yield from self.run_until_error('/bin/ip', 'route', 'del', 'all',
                'table', table_id)
