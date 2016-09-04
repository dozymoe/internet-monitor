# Internet Monitor

## Using

You need to run main.py as a service/daemon.

You need something like this in your syslog configuration (mine uses
syslog-ng):

    destination internet_monitor { udp("127.0.0.1" port(1979)); };
    log { source(src); destination(internet_monitor); };
