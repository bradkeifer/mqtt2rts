# mqtt2rts

Exposes the Somfy RS485 RTS Transmitter to a MQTT broker

Usage
-----

```bash

usage: mqtt2rts [-h] [--config_file CONFIG_FILE]
                [--log_level {debug,info,warning,error,critical}]
                [--broker_host BROKER_HOST] [--broker_port BROKER_PORT]
                [--username USERNAME] [--password PASSWORD]
                [--rts_host RTS_HOST] [--rts_port RTS_PORT]
                [--keepalive KEEPALIVE] [--channels CHANNELS]

Expose somfy RS485 RTS Transmitter to an MQTT broker

optional arguments:
  -h, --help            show this help message and exit
  --config_file CONFIG_FILE
                        Configuration file
  --log_level {debug,info,warning,error,critical}
                        Set logging level. Defaults to error.
  --broker_host BROKER_HOST
                        The hostname or IP address of the MQTT broker.
                        Defaults to localhost.
  --broker_port BROKER_PORT
                        The MQTT broker port. Defaults to 1883.
  --username USERNAME   The MQTT Username, if required.
  --password PASSWORD   The MQTT Password, if required.
  --rts_host RTS_HOST   The hostname or IP address of the Somfy RTS
                        Transmitter. Defaults to localhost.
  --rts_port RTS_PORT   The Somfy RTS Transmitter port. Defaults to 4660.
  --keepalive KEEPALIVE
                        The ping period to apply for both MQTT and RTS
                        connections. Defaults to 60 secs.
  --channels CHANNELS   The number of RTS channels to manage. Defaults to 16.

```

TODO
----

* Develop documentation
* Broaden the MQTT broker connectivity options
