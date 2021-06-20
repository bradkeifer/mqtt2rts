#!/usr/bin/env python3
# mqtt2rts - Exposes the somfy RS485 RTS transmitter to an MQTT broker
import paho.mqtt.client as mqtt
import logging
import logging.handlers
import argparse
import sys
import json
import somfy.rts as somfy
from select import select
import configparser


# Our MQTT related constants
MQTT_DISCOVERY_PREFIX = 'homeassistant'
MQTT_COMPONENT = 'cover'
MQTT_CONFIG_TOPIC = 'config'
MQTT_CMD_TOPIC = 'cmd'
MQTT_STATE_TOPIC = 'state'
MQTT_POSITION_TOPIC = 'position'
MQTT_SET_POSITION_TOPIC = 'set_position'
MQTT_AVAILABILITY_TOPIC = 'availability'
MQTT_PAYLOAD_OPEN = 'up'
MQTT_PAYLOAD_CLOSE = 'down'
MQTT_PAYLOAD_STOP = 'stop'
MQTT_POSITION_OPEN = 0
MQTT_POSITION_CLOSED = 100
MQTT_PAYLOAD_AVAILABLE = 'online'
MQTT_PAYLOAD_NOT_AVAILABLE = 'offline'
MQTT_STATE_OPEN = 'open'
MQTT_STATE_CLOSED = 'closed'
MQTT_STATE_UNKNOWN = 'unknown'

# Other Constants
PROG = 'mqtt2rts'

LOGGING_LEVEL = {
    'debug': logging.DEBUG,
    'info': logging.INFO,
    'warning': logging.WARNING,
    'error': logging.ERROR,
    'critical': logging.CRITICAL,
}


# MQTT callback functions
def on_connect(client, userdata, flags, rc):
    """The callback for when we receive the CONNACK response from the MQTT broker."""
    if rc == 0:
        logger.info('MQTT broker connection established')
        # Publish info about us so Home Assistant can discover us
        for node_address, node_label in nodes.items():
            node_address_str = f'0x{node_address:06x}'
            client.publish(MQTT_DISCOVERY_PREFIX + '/' + MQTT_COMPONENT + '/' +
                           node_label + '/' + MQTT_AVAILABILITY_TOPIC,
                           payload=MQTT_PAYLOAD_AVAILABLE, retain=True)

            mqtt_config = {'qos': 0, 'retain' : True, 'optimistic' : False}
            mqtt_config['device_class'] = 'shade'
            mqtt_config['availability_topic'] = MQTT_DISCOVERY_PREFIX + '/' + \
                                                MQTT_COMPONENT + '/' + \
                                                node_label + '/' + \
                                                MQTT_AVAILABILITY_TOPIC 
            mqtt_config['payload_open'] = MQTT_PAYLOAD_OPEN
            mqtt_config['payload_close'] = MQTT_PAYLOAD_CLOSE
            mqtt_config['payload_stop'] = MQTT_PAYLOAD_STOP
            mqtt_config['position_open'] = MQTT_POSITION_OPEN
            mqtt_config['position_closed'] = MQTT_POSITION_CLOSED
            mqtt_config['payload_available'] = MQTT_PAYLOAD_AVAILABLE
            mqtt_config['payload_not_available'] = MQTT_PAYLOAD_NOT_AVAILABLE
            mqtt_config['state_open'] = MQTT_STATE_OPEN
            mqtt_config['state_closed'] = MQTT_STATE_CLOSED
            mqtt_config['position_template'] = '{{ value.x }}'
            # The following two device registry entries seem to cause problems for homeassistant
            # Not entirely sure why, as I think the payload conforms to the documentation
            mqtt_config['device'] = {'identifiers': [node_label, node_address_str],
                                     'manufacturer': 'Somfy', 
                                     'model': 'RTS 485 Transmitter'}
#            mqtt_config['manufacturer'] = 'Somfy'
#            mqtt_config['model'] = 'RTS 485 Transmitter'
            for i in range(config.getint(node_address_str, 'channels')):
                if config.has_option(node_address_str, f'channel {i} name'):
                    mqtt_config['name'] = config[node_address_str][f'channel {i} name']
                else:
                    mqtt_config['name'] = node_label + str(i)
                    
#                mqtt_config['unique_id'] = f"UID{node_address:06x}{mqtt_config['name']}"
                mqtt_config['unique_id'] = node_label + str(i)
                mqtt_config['command_topic'] = MQTT_DISCOVERY_PREFIX + '/' + \
                                               MQTT_COMPONENT + '/' + \
                                               node_label + str(i) + '/' + \
                                               MQTT_CMD_TOPIC 
                mqtt_config['state_topic'] = MQTT_DISCOVERY_PREFIX + '/' + \
                                             MQTT_COMPONENT + '/' + \
                                             node_label + str(i) + '/' + \
                                             MQTT_STATE_TOPIC 
                mqtt_config['position_topic'] = MQTT_DISCOVERY_PREFIX + '/' + \
                                                MQTT_COMPONENT + '/' + \
                                                node_label + str(i) + '/' + \
                                                MQTT_POSITION_TOPIC 
                mqtt_config['set_position_topic'] = MQTT_DISCOVERY_PREFIX + '/' + \
                                                    MQTT_COMPONENT + '/' + \
                                                    node_label + str(i) + '/' + \
                                                    MQTT_SET_POSITION_TOPIC 
                json_payload = json.dumps(mqtt_config, indent=4)
                
                client.publish(MQTT_DISCOVERY_PREFIX + '/' + MQTT_COMPONENT + '/' +
                               node_label + str(i) + '/' + MQTT_CONFIG_TOPIC,
                               payload=json_payload, retain=True)
                client.subscribe(MQTT_DISCOVERY_PREFIX + '/' + MQTT_COMPONENT + '/'  +
                                 node_label + str(i) + '/' + MQTT_CMD_TOPIC)
                client.subscribe(MQTT_DISCOVERY_PREFIX + '/' + MQTT_COMPONENT + '/'  +
                                 node_label + str(i) + '/' + MQTT_SET_POSITION_TOPIC)
    elif rc == 1:
        logger.error('MQTT broker connection error: Connection refused - '
                     'incorrect protocol version.')
        sys.exit(1)
    elif rc == 2:
        logger.error('MQTT broker connection error: Connection refused - '
                     'invalid client identifier.')
        sys.exit(1)
    elif rc == 3:
        logger.error('MQTT broker connection error: Connection refused - '
                     'server unavailable.')
        sys.exit(1)
    elif rc == 4:
        logger.error('MQTT broker connection error: Connection refused - '
                     'bad username or password.')
        sys.exit(1)
    elif rc == 5:
        logger.error('MQTT broker connection error: Connection refused - '
                     'not authorised.')
        sys.exit(1)
    else:
        logger.error(f'MQTT broker connection error 0x{rc:x}')
        sys.exit(1)


def on_message(client, userdata, msg):
    """The callback for when a PUBLISH message is received from the MQTT Broker."""
    logger.debug('on_message:' + msg.topic + ' ' + str(msg.payload))
    
    # Determine topic
    topic_list = msg.topic.split('/')
    
    # Check that it is a topic we can leigitimately process
    if (topic_list[0] != MQTT_DISCOVERY_PREFIX or
        topic_list[1] != MQTT_COMPONENT):        
        logger.warning('Invalid topic received: ' + msg.topic)
        logger.debug('Expected ' + MQTT_DISCOVERY_PREFIX + ', but got ' + topic_list[0])
        logger.debug('Expected ' + MQTT_COMPONENT + ', but got ' + topic_list[1])
        return None
    
    # Identify the node from our dictionary of nodes
    node_address = 0
    node_label = b''
    for k, v in nodes.items():
        if topic_list[2].startswith(v):
            node_address_str = f'0x{k:06x}'
            node_label = v
            logger.debug(f'topic_list[2] ({topic_list[2]}) resolves to '
                         f'node address ({node_address_str}), '
                         f'node label ({node_label}).')
            break
        
    if (not topic_list[2].startswith(node_label) or
        not topic_list[2].lstrip(node_label).isdigit()):
        logger.warning('Invalid topic received: ' + msg.topic)
        logger.debug('topic_list[2] = ' + topic_list[2] )
        if not topic_list[2].startswith(node_label):
            logger.debug('Expected ' + topic_list[2] + ' to start with ' + node_label)
        if not topic_list[2].lstrip(node_label).isdigit():
#        if not topic_list[2].removeprefix(node_label).isdigit():
            logger.debug('Expected ' + topic_list[2] + ' to end with a digit')
        return None

    if topic_list[3] == MQTT_CMD_TOPIC:
        rts_channel = int(topic_list[2].lstrip(node_label))
#        rts_channel = int(topic_list[2].removeprefix(node_label))

#        if rts_channel >= args.channels:
        if rts_channel >= config.getint(node_address_str, 'channels'):
            # Outside the range of channels we manage
            logger.warning(f'Channel {rts_channel} is outside our range '
                           f'(0-{config[node_address_str]["channels"]}) for node '
                           f'address {node_address_str}.')
            logger.warning('Ignoring command')
            return None
        
        if config.has_option(node_address_str, f'channel {rts_channel} name'):
            name = config[node_address_str][f'channel {rts_channel} name']
        else:
            name = f'{node_label}{rts_channel}'
            
        if (msg.payload.decode() == MQTT_PAYLOAD_OPEN):
            logger.info(f'Received Open command for channel {rts_channel}, '
                        f'name {name}.')
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.UP, rts_channel)
            if success:
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_OPEN, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(MQTT_POSITION_OPEN), retain = True)
                
        elif (msg.payload.decode() == MQTT_PAYLOAD_CLOSE):
            logger.info(f'Received Close command for channel {rts_channel}, '
                        f'name {name}.')
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.DOWN, rts_channel)
            if success:
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_CLOSED, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(MQTT_POSITION_CLOSED), retain = True)
                
        elif (msg.payload.decode() == MQTT_PAYLOAD_STOP):
            logger.info(f'Received Stop command for channel {rts_channel}, '
                        f'name {name}.')
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.STOP, rts_channel)
            if success:
                # Hmmm. We are neither open nor closed now - not sure what the
                # correct state should be??
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_UNKNOWN, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(abs(MQTT_POSITION_CLOSED - \
                                                 MQTT_POSITION_OPEN) // 2),
                               retain = True)
                
        else:
            logger.error('Invalid payload: ' + msg.payload.decode())
            logger.error('Should be one of: ' + MQTT_PAYLOAD_OPEN +
                         ' or ' + MQTT_PAYLOAD_CLOSE +
                         ' or ' + MQTT_PAYLOAD_STOP + '.')
            success = False
        
    elif topic_list[3] == MQTT_SET_POSITION_TOPIC:
        rts_channel = int(topic_list[2].lstrip(node_label))
        if msg.payload.isdigit():
            position = int(msg.payload)
        else:
            logger.error('Set Position topic payload (%s) is non-numeric.',
                         str(msg.payload))
            return None
        
        logger.info(f'Received Set Position command for channel {rts_channel}, '
                    f'name {name}.')
        logger.info('Payload is %d.', position)
        if position == MQTT_POSITION_OPEN:
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.UP, rts_channel)
            if success:
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_OPEN, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(MQTT_POSITION_OPEN), retain = True)
                
        elif position == MQTT_POSITION_CLOSED:
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.DOWN, rts_channel)
            if success:
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_CLOSED, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(MQTT_POSITION_CLOSED), retain = True)
                
        else:
            success = somfy.control_position(int(node_address_str, base=16),
                                             somfy.MY, rts_channel)
            if success:
                # Hmmm. We are neither open nor closed now - not sure what the
                # correct state should be??
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_STATE_TOPIC,
                               payload = MQTT_STATE_UNKNOWN, retain = True)
                client.publish(MQTT_DISCOVERY_PREFIX + '/' +
                               MQTT_COMPONENT + '/' +
                               node_label + str(rts_channel) + '/' +
                               MQTT_POSITION_TOPIC,
                               payload = str(position), retain = True)
    else:
        return None

    return success

def my_loop_forever():
    """Maintain both MQTT Broker and Somfy RTS connectivity"""
    
    while True:
        logger.debug("Selecting for reading" + (" and writing" if mqtt_client.want_write() else ""))
        r, w, e = select(
            [mqtt_sock],
            [mqtt_sock] if mqtt_client.want_write() else [],
            [],
            1
        )
        
        if mqtt_sock in r:
            logger.debug("MQTT Socket is readable, calling loop_read()")
            mqtt_client.loop_read()
        
        if mqtt_sock in w:
            logger.debug("MQTT Socket is writable, calling loop_write()")
            mqtt_client.loop_write()
        
        logger.debug("my_loop_forever(): Calling somfy.loop_misc()")
        somfy.loop_misc()
        logger.debug("my_loop_forever(): Calling mqtt_client.loop_misc()")
        mqtt_client.loop_misc()

# Parse arguments
parser = argparse.ArgumentParser(description=
                                 'Expose somfy RS485 RTS Transmitter to an MQTT broker')
parser.add_argument('--config_file', help='Configuration file')
parser.add_argument('--log_level',
                    help='Set logging level. Defaults to error.',
                    choices=['debug', 'info', 'warning', 'error', 'critical'],
                    default='error')
parser.add_argument('--broker_host', help='The hostname or IP address of the MQTT broker.'
                    ' Defaults to localhost.', default='localhost')
parser.add_argument('--broker_port', help='The MQTT broker port. '
                    'Defaults to 1883.', type=int, default=1883)
parser.add_argument('--username', help='The MQTT Username, if required.')
parser.add_argument('--password', help='The MQTT Password, if required. ')
parser.add_argument('--rts_host', help=
                    'The hostname or IP address of the Somfy RTS Transmitter. '
                    'Defaults to localhost.', default='localhost')
parser.add_argument('--rts_port', help =
                    'The Somfy RTS Transmitter port. Defaults to 4660.',
                    type=int, default=4660)
parser.add_argument('--keepalive', help =
                    'The ping period to apply for both MQTT and RTS connections. Defaults to 60 secs.',
                    type=int, default=60)
parser.add_argument('--channels', help = 'The number of RTS channels to manage. '
                    'Defaults to 16.', type=int, default=16)
args = parser.parse_args()

if args.config_file:
    config = configparser.ConfigParser()
    config.read(args.config_file)
else:
    config = {}
    
    config['MQTT'] = {}
    config['MQTT']['log level'] = args.log_level
    config['MQTT']['keepalive'] = str(args.keepalive)
    config['MQTT']['host'] = args.broker_host
    config['MQTT']['port'] = str(args.broker_port)
    config['MQTT']['username'] = args.username
    config['MQTT']['password'] = args.password
    
    config['RTS'] = {}
    config['RTS']['connection method'] = 'socket'
    config['RTS']['log level'] = args.log_level
    config['RTS']['keepalive'] = str(args.keepalive)
    config['RTS']['host'] = args.rts_host
    config['RTS']['port'] = str(args.rts_port)
    config['RTS']['nodes'] = ''
    

# Establish logging
logger = logging.getLogger(PROG)
logger.setLevel(LOGGING_LEVEL[config['MQTT']['log level']])

# create handler and set level
# ch = logging.handlers.SysLogHandler(address='/dev/log')
ch = logging.StreamHandler()
ch.setLevel(LOGGING_LEVEL[config['MQTT']['log level']])

# create formatter
formatter = logging.Formatter('%(levelname)s: %(message)s')

# add formatter to handler
ch.setFormatter(formatter)

# add handler to logger
logger.addHandler(ch)

# Establish RTS Transmitter connection
logger.debug('Establish RTS Transmitter connection')
somfy = somfy.RTSProtocol()
somfy.enable_logger(logger)

somfy.connect(host=config['RTS']['host'],
              port=int(config['RTS']['port']),
              keepalive=int(config['RTS']['keepalive']))

somfy_sock = somfy.socket()

if not config.has_option('RTS','node addresses'):
    nodes = somfy.get_nodes()
else:
    nodes = {}
    node_list = config['RTS']['node addresses'].split(',')
    for node in node_list:
        logger.debug(f'Node is {node} in node_list {node_list}.')
        if config.has_option(node, 'node label'):
            nodes[int(node, base=16)] = config[node]['node label']
            if config.has_option(node, 'set node label') and \
               config.getboolean(node, 'set node label'):
                # Set the node label in the RTS Transmitter to match the config
                somfy.set_node_label(int(node, base=16), nodes[int(node, base=16)])
        else:
            # Read the node label from the RTS Transmitter
            nodes[int(node, base=16)] = somfy.get_node_label(int(node, base=16))
            if len(nodes[int(node, base=16)]) == 0:
                # Use hex representation of the node address as the label
                nodes[int(node, base=16)] = node
        
        if not config.has_option(node, 'channels'):
            # Coerce the channels from args
            config[node]['channels'] = str(args.channels)
            
logger.info(f'Nodes are {nodes}')


# Establish MQTT communications and callbacks
logger.debug('Establish MQTT communications and callbacks')
mqtt_client = mqtt.Client(PROG)  # create new instance
mqtt_client.on_connect = on_connect   # bind callback functions
mqtt_client.on_message = on_message
mqtt_client.enable_logger(logger)    # enable logging of MQTT data
mqtt_client.username_pw_set(username=config['MQTT']['username'],
                            password=config['MQTT']['password'])
mqtt_client.will_set(MQTT_DISCOVERY_PREFIX + '/' + MQTT_COMPONENT +
                     '/' + PROG + '/' +
                     MQTT_AVAILABILITY_TOPIC,
                     payload=MQTT_PAYLOAD_NOT_AVAILABLE, retain=True)
mqtt_client.connect(host=config['MQTT']['host'],
                    port=int(config['MQTT']['port']),
                    keepalive=int(config['MQTT']['keepalive']))
mqtt_sock = mqtt_client.socket()

# Start loop
logger.debug('About to enter my_loop_forever() ... wish me luck!')
my_loop_forever()
#mqtt_client.loop_forever()
