#!/usr/bin/env python3

import asyncio
import logging
from functools import partial
from signal import SIGINT, SIGTERM

from runner import Runner
from syslog_handler import SysLogHandler

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

loop = asyncio.get_event_loop()

runner = Runner(
    loop,
    {
        'wlp0s18f2u3': {'active': True},
        'wlp0s18f2u4': {'active': True},
    },
    log)

def signal_handler(signal):
    log.info('Closing.')
    loop.stop()

loop.add_signal_handler(SIGINT, partial(signal_handler, SIGINT))
loop.add_signal_handler(SIGTERM, partial(signal_handler, SIGTERM))

try:
    loop.create_task(runner.setup_routing())

    # TODO: figure out how to assign properties to protocol
    SysLogHandler.runner = runner
    SysLogHandler.log = log

    server = loop.create_datagram_endpoint(SysLogHandler,
            local_addr=('127.0.0.1', 1979))

    transport, protocol = loop.run_until_complete(server)

    loop.run_forever()
finally:
    transport.close()
    loop.close()
