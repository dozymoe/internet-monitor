#!/usr/bin/env python
# -*- coding: utf-8 -*-
#
# Copyright 2015-2015 Fireh <dozymoe@gmail.com>
#
# Watch wireless connection, update network route for multiple uplinks.
# Read more here: http://lartc.org/howto/lartc.rpdb.multiple-links.html
#
# Requirements:
#   - Gentoo
#   - something like the code below in /etc/syslog-ng/syslog-ng.conf
#
#     source s_wpa_supplicant { system(); };
#     destination internet_monitor { unix-dgram("/run/internet_monitor.sock"); };
#     log { source(s_wpa_supplicant); destination(internet_monitor); };
#
#   - and something like the code below in /etc/conf.d/net
#
#     wpa_supplicant_wlp2s0="-s"
#     wpa_supplicant_wlp0s29u1u3u2="-s"
#
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, see <http://www.gnu.org/licenses/>.

import logging
from logging.handlers import RotatingFileHandler
import os
try:
    import socketserver
except ImportError:
    import SocketServer as socketserver
import re
import subprocess
import signal
from time import sleep
from threading import Lock, Thread

SOCKET_FILE = '/run/internet_monitor.sock'
BASE_DIR = os.path.dirname(os.path.realpath(__file__))
MULTIPATH_TABLE = 323

wlan = {
    'wlan0': {
        'active': False,
        'test_ip': 'google.co.id',
        'has_reconnect_thread': False,
        #'weight': 2,
        'local_ip': None,
        'network': None,
        'route': None,
    },
    'wlan1': {
        'active': True,
        'test_ip': 'google.co.id',
        'has_reconnect_thread': False,
        'local_ip': None,
        'network': None,
        'route': None,
    },
    #'wlan2': {
    #    'active': False,
    #    'test_ip': 'google.co.id',
    #    'has_reconnect_thread': False,
    #    'local_ip': None,
    #    'network': None,
    #    'route': None,
    #},
}
regex_remote_ip = re.compile(r'inet [0-9./]+ brd ([0-9.]+)')
initted = False
running = True
socket = None
reconnect_lock = Lock()

logging.basicConfig()
log = logging.getLogger(__name__)
log.setLevel(logging.DEBUG)

REGEX_ROUTE = re.compile(r'(\w+): adding default route (.*)')

def signal_handler(signum, frame):
    print('CLOSING!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!')
    global running
    running = False
    if not socket is None:
        socket.shutdown()


def shell(command):
    print(command)
    try:
        subprocess.check_call(command, shell=True, preexec_fn=os.setpgrp)
        ret = 0
    except Exception as e:
        #print(e, command)
        ret = 1
    return ret


def restart_network(intf):
    wlan[intf]['local_ip'] = None
    wlan[intf]['network'] = None
    wlan[intf]['route'] = None
    wlan[intf]['connected'] = False
    subprocess.Popen(['/etc/init.d/net.%s' % intf, 'restart'])


def reconnect_thread_callback(interface):
    global wlan, running
    if not wlan[interface]['active']:
        return
    if wlan[interface]['has_reconnect_thread']:
        return
    wlan[interface]['has_reconnect_thread'] = True
    while running and not wlan[interface]['connected']:
        sleep(60)
        # CalledProcessError
        cmd = '/bin/ping -qn -I {inf} -c 2 {ip}'.format(inf=interface,
                ip=wlan[interface]['test_ip'])
        prc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = prc.communicate()
        if hasattr(out, 'decode'):
            out = out.decode('utf-8')
        matches = re.findall(r'(\d+) packets transmitted', out)
        ping_success = len(err) == 0 and len(matches) and matches[0] != '0'
        if not ping_success:
            log.debug('ping success: %s; matches: %s; output: %s; error: %s' % (
                    ping_success, matches, out, err))
            restart_network(interface)
    wlan[interface]['has_reconnect_thread'] = False


class SyslogHandler(socketserver.BaseRequestHandler):
    
    def parse_wlan(self, line):
        global running
        if not running:
            return

        match = REGEX_ROUTE.search(line)
        if match:
            route_intf = wlan.get(match.group(1))
            if route_intf is None or route_intf['active'] == False:
                shell('ip route del default dev %s' % match.group(1))
                return

        for intf in wlan:
            if not wlan[intf]['active']:
                continue
            match = wlan[intf]['regex_ip'].search(line)
            if match:
                # local ip
                wlan[intf]['local_ip'] = match.group(1)
                log.debug('local_ip changed for ' + intf)
                ## remote ip
                #ipaddr = subprocess.check_output(['/bin/ip', 'addr', 'show',
                #        'dev', intf])
                #match = regex_remote_ip.search(ipaddr)
                #if match:
                #    wlan[intf]['remote_ip'] = match.group(1)
                return

            match = wlan[intf]['regex_network'].search(line)
            if match:
                wlan[intf]['network'] = match.group(1)
                log.debug('network changed for ' + intf)
                return

            match = wlan[intf]['regex_route'].search(line)
            if match:
                wlan[intf]['route'] = '%s dev %s' % (match.group(1), intf)
                log.debug('route changed for ' + intf)
                if wlan[intf]['connected']:
                    return

                wlan[intf]['connected'] = wlan[intf].get('route') and \
                        wlan[intf].get('network') and \
                        wlan[intf].get('local_ip')

                if wlan[intf]['connected']:
                    log.info('new internet connection ' + \
                            wlan[intf]['route'])
                    self.reroute()
                    shell('ntpclient -s -h id.pool.ntp.org')
                return

            if wlan[intf]['regex_remove'].match(line):
                wlan[intf]['connected'] = False
                wlan[intf]['local_ip'] = None
                wlan[intf]['network'] = None
                wlan[intf]['route'] = None
                log.info('lost internet connection ' + intf)
                self.reroute()
                Thread(target=reconnect_thread_callback,
                        kwargs={'interface':  intf}).start()


    def reroute(self):
        with reconnect_lock:
            self._reroute()


    def _reroute(self):
        log.info('rerouting...')

        log.info('removing old rules')
        while not shell('/bin/ip rule delete table main &> /dev/null'):
            pass
        for ii in range(len(wlan)):
            while not shell('/bin/ip rule delete table %s &> /dev/null'\
                    % (200 + ii + 1)):
                pass
        while not shell('/bin/ip rule delete table %s &> /dev/null' %\
                MULTIPATH_TABLE):
            pass

        log.info('flushing tables')
        for ii in range(len(wlan)):
            shell('/bin/ip route flush table %s' % (200 + ii + 1))
        shell('/bin/ip route flush table %s' % MULTIPATH_TABLE)

        log.info('removing tables')
        for ii in range(len(wlan)):
            shell('/bin/ip route del table %s &> /dev/null' %\
                    (200 + ii + 1))
        shell('/bin/ip route del table %s &> /dev/null' % MULTIPATH_TABLE)

        log.info('set new routing rules')

        # main table without default gateway
        shell('/bin/ip rule add prio 50 table main')
        defroutes = subprocess.check_output(
                ['/bin/ip', 'route', 'show'], universal_newlines=True)

        for defroute in defroutes.splitlines():
            if not defroute.startswith('default '):
                continue
            shell('/bin/ip route del %s &> /dev/null' % defroute)

        for ii, intf in enumerate(wlan):
            if not wlan[intf]['active']:
                continue
            log.info('set new route for %s' % intf)
            if not wlan[intf]['connected']:
                log.info('new route for %s skipped' % intf)
                continue
            table_id = 200 + ii + 1
            shell('/bin/ip rule add prio %s from %s table %s' %
                  (table_id, wlan[intf]['local_ip'], table_id))

            shell(('/bin/ip route add default table %s proto static '+
                    '%s src %s ') % (table_id, wlan[intf]['route'],
                    wlan[intf]['local_ip']))

            shell(('/bin/ip route append prohibit default table %s '+
                    'metric 1 proto static') % table_id)

            shell(('/sbin/iptables -t nat -A POSTROUTING -o %s '+
                    '-j MASQUERADE') % intf)

        shell('/bin/ip rule add prio %s table %s' % (MULTIPATH_TABLE,
                MULTIPATH_TABLE))

        hops = [x for x in wlan if wlan[x]['active'] and wlan[x]['connected']]
        load_balancing = ('/bin/ip route add default table %s '+
                'proto static ') % MULTIPATH_TABLE
        if len(hops) == 0:
            pass
        elif len(hops) == 1:
            load_balancing += wlan[hops[0]]['route']
            shell(load_balancing)
        else:
            for intf in hops:
                load_balancing += ' nexthop %s weight %s' % (
                        wlan[intf]['route'], wlan[intf].get('weight', 1))
            shell(load_balancing)

        shell('/bin/ip route flush cache')


    def handle(self):
        line = self.request[0].strip().decode('utf-8')
        #log.debug('From syslog: ' + line)
        self.parse_wlan(line)

        global initted
        if not initted:
            initted = True
            for intf in wlan:
                if not wlan[intf]['active']:
                    continue
                restart_network(intf)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)
# init
hdlr = RotatingFileHandler(os.path.join(BASE_DIR, 'main.log'),
        maxBytes=1024*1024, backupCount=2)
formatter = logging.Formatter('%(asctime)s %(levelname)s %(message)s')
hdlr.setFormatter(formatter)
log.addHandler(hdlr)

log.info('Opening socket...')

for intf in wlan:
    wlan[intf]['connected'] = False
    wlan[intf]['regex_ip'] = re.compile(r'%s: leased ([\d.]+)' % intf)
    wlan[intf]['regex_network'] = re.compile(r'%s: adding route to (.*)'\
            % intf)
    wlan[intf]['regex_route'] = re.compile(r'%s: adding default route (.*)'\
            % intf)
    wlan[intf]['regex_remove'] = re.compile(r'.*\s%s: removing interface$'\
            % intf)


def datagram_thread_callback():
    global socket
    socket = socketserver.UnixDatagramServer(SOCKET_FILE, SyslogHandler)
    os.chmod(SOCKET_FILE, 0o777)
    try:
        socket.serve_forever()
    except KeyboardInterrupt:
        pass
    except Exception:
        log.exception('UNKNOWN ERROR HAPPENED')


# main
log.info('Listening...')
server = Thread(target=datagram_thread_callback)
server.start()
while running:
    sleep(1)
print('server thread join')
server.join()

# destroy
os.remove(SOCKET_FILE)
log.info('Done')
