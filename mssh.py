#!/usr/bin/env python
#encoding: utf-8

import logging
import time
import json
import socket
import subprocess
import random


HOSTNAME = socket.getfqdn()


#### Messages and related classes ####################
class MalformedMessage(Exception):
    pass


class Message(dict):
    def __init__(self, m_type, token, **kwargs):
        self['token'] = token
        self['m_type'] = m_type

    def __str__(self):
        return json.dumps(self)

    @classmethod
    def from_str(cls, cmd_str):
        try:
            cmd_dict = json.loads(cmd_str)
            return cls(**cmd_dict)
        except (ValueError, TypeError) as exc:
            raise MalformedMessage('%s\n%s' % (cmd_str, exc))


class Token(Message):
    def __init__(self, token=None, **kwargs):
        self.token = token or self.generate_token()
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(Token, self).__init__('token', self.token, **kwargs)
        self['host'] = HOSTNAME

    @staticmethod
    def generate_token():
        rand = str(random.randint(0, 9999))
        ts = repr(time.time()).replace('.', '')
        return rand + ts


class BadToken(Message):
    def __init__(self, token, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(BadToken, self).__init__('bad_token', token, **kwargs)
        self['m_type'] = 'bad_token'
        self['host'] = HOSTNAME


class CommandRequest(Message):
    def __init__(self, token, command, return_queue, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(CommandRequest, self).__init__('command_request', token,
                                             **kwargs)
        self['command'] = command
        self['return_queue'] = return_queue
        self['m_type'] = 'command_request'


class CommandResult(Message):
    def __init__(self, token, command, return_queue,
                 rc='', stdout='', stderr='', host=HOSTNAME, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(CommandResult, self).__init__('command_result', token, **kwargs)
        self['token'] = token
        self['command'] = command
        self['host'] = host
        self['return_queue'] = return_queue
        self['rc'] = rc
        self['stdout'] = stdout
        self['stderr'] = stderr
        self.finished = False
        self.proc = None

    def run(self):
        self.proc = subprocess.Popen(
            self['command'], shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

    def parse_results(self):
        self['rc'] = self.proc.wait()
        self['stdout'] = self.proc.stdout and self.proc.stdout.read() or ''
        self['stderr'] = self.proc.stderr and self.proc.stderr.read() or ''
        self['m_type'] = 'command_result'

    def __getattr__(self, name):
        return getattr(self.proc, name)


MSG_TYPES = {
    'command_result': CommandResult,
    'command_request': CommandRequest,
    'token': Token,
    'bad_token': BadToken,
}


def to_message(str_msg):
    try:
        dict_obj = json.loads(str_msg)
        return MSG_TYPES[dict_obj['m_type']](**dict_obj)
    except ValueError as exc:
        raise MalformedMessage('Unable to parse json: %s\n%s'
                               % (str_msg, exc))
    except TypeError as exc:
        raise MalformedMessage('Missing or duplicate fields: %s\n%s'
                               % (str_msg, exc))


######## Helper methods and classes #########################
class CommandPool(object):
    def __init__(self, conn, max_commands=2):
        self.max_commands = 2
        self.pool = {}
        self.conn = conn
        self.init_poll()

    def init_poll(self):
        for _ in range(self.max_commands):
            new_token = Token()
            self.pool[new_token.token] = None
            self.send_token(new_token)

    def send_token(self, token):
            self.send_msg(token, '/queue/ctrl_%s' % HOSTNAME)

    def send_bad_token(self, token, ret_queue):
        bad_token = BadToken(token)
        self.send_msg(bad_token, ret_queue)

    def send_result(self, cmd):
        cmd.parse_results()
        self.send_msg(cmd, cmd['return_queue'])

    def poll(self):
        finished = []
        for token, cmd in self.pool.iteritems():
            if cmd and cmd.poll() is not None:
                finished.append(token)
        for token in finished:
            self.send_result(self.pool[token])
            del self.pool[token]
            ## generate a new token and clear executor slot
            new_token = Token()
            self.pool[new_token.token] = None
            self.send_token(new_token)

    def add_command(self, cmd_req):
        token = cmd_req['token']
        if token in self.pool and not self.pool[token]:
            cmd_res = CommandResult.from_str(str(cmd_req))
            cmd_res.run()
            self.pool[token] = cmd_res
        elif token not in self.pool:
            logging.warn("Received a bad token: %s" % cmd_req)
            self.send_bad_token(token, cmd_req['return_queue'])

    def send_msg(self, msg, queue):
        self.conn.send(str(msg), destination=queue)


def show_results(results, hosts, error_only=False):
    global_rc = 0
    for host in hosts:
        if host in results:
            res = results[host]
            res_status = res['rc'] and 'error' or 'ok'
            if res['rc'] or not error_only:
                print "%s::%s::Result" % (host, res_status)
            if res['stdout'] and (res['rc'] or not error_only):
                print '\n'.join(
                    ("%s::%s::stdout::" % (host, res_status) + line
                     for line
                     in res['stdout'].split('\n')
                     if line))
            if res['stderr'] and (res['rc'] or not error_only):
                print '\n'.join(
                    ("%s::%s::stderr::" % (host, res_status) + line
                     for line
                     in res['stderr'].split('\n')
                     if line))
            if res['rc'] or not error_only:
                print "%s::%s::Return code: %d" % (host, res_status,
                                                   res['rc'])
            if error_only and not res['rc']:
                print '%s::ok' % host
            global_rc = global_rc or res['rc']
        else:
            global_rc = 1
            print "%s::error::Timeout" % host
    return global_rc


def show_summary(results, hosts):
    global_rc = 0
    for host in hosts:
        if host in results:
            print results[host]
            if results[host]['rc']:
                print "%s::error" % host
            else:
                print "%s::ok" % host
        else:
            print "%s::error::timeout" % host
    return global_rc


######### Listener classes ###############################
class BaseListener():
    def start_conn(self):
        self.conn.set_listener('', self)
        self.conn.start()
        self.conn.connect()

    def on_error(self, headers, message):
        logging.error("HEADERS:\n%s\nMESSAGE:\n%s" % (headers, message))
        raise Exception("HEADERS:\n%s\nMESSAGE:\n%s" % (headers, message))

    def on_connecting(self, *args):
        logging.debug('on_connecting')

    def on_send(self, *args):
        logging.debug('on_send')


class ServerListener(BaseListener):
    def __init__(self, server, port, conn, max_procs=2):
        self.server = server
        self.port = port
        self.conn = conn
        self.tokens = []

        self.start_conn()
        self.pool = CommandPool(conn, max_procs)
        in_queue = '/queue/in_%s' % HOSTNAME
        self.conn.subscribe(destination=in_queue, ack='auto')

    def poll(self):
        self.pool.poll()

    def on_message(self, headers, message):
        logging.info("Got command: %s" % message)
        try:
            cmd_req = to_message(message)
        except MalformedMessage as exc:
            logging.error('Unalbe to process command %s: %s'
                          % (message, exc))
            return
        self.pool.add_command(cmd_req)


class ClientListener(BaseListener):
    def __init__(self, server, port, command, conn, hosts):
        self.server = server
        self.port = port
        self.conn = conn
        self.return_queue = '/queue/return_%s' % HOSTNAME
        self.command = command
        self.hosts = {h: None for h in hosts}
        self.results = {}
        self.start_conn()
        self.subscribe_for_tokens()
        self.finished = False

    def subscribe_for_tokens(self):
        for host in self.hosts.iterkeys():
            ctrl_queue = '/queue/ctrl_%s' % host
            self.hosts[host] = 'wait_for_token'
            self.conn.subscribe(destination=ctrl_queue, ack='client')

    def handle_token(self, headers, message):
        host = headers['destination'].split('_', 1)[1]
        ## this should not happen, but just in case
        if not self.hosts[host] == 'wait_for_token':
            return
        token_msg = to_message(message)
        logging.info("::%s::Got token: %s, sending command"
                     % (host, token_msg['token']))
        command = CommandRequest(command=self.command,
                                 token=token_msg['token'],
                                 return_queue=self.return_queue)
        in_queue = '/queue/in_%s' % host
        self.conn.send(str(command), destination=in_queue)
        self.conn.ack({'message-id': headers['message-id']})
        self.conn.unsubscribe(destination='/queue/ctrl_%s' % host)
        self.conn.subscribe(destination=self.return_queue,
                            ack='client-individual')
        logging.debug('::%s::Command sent, waiting for response' % host)
        self.hosts[host] = token_msg['token']

    def handle_result(self, headers, message):
        logging.info('Got response %s' % message)
        try:
            message = to_message(message)
        except MalformedMessage as exc:
            logging.warn('Unable to parse response %s: %s'
                         % (message, exc))
            return
        ## check if the message was meant to us (this process)
        if message['host'] not in self.hosts:
            logging.info("Wrong host %s, ignoring" % message['host'])
            return
        elif message['token'] != self.hosts[message['host']]:
            logging.info("Bad token %s, expecting %s, ignoring message"
                         % (message['token'],
                            self.hosts[message['host']]))
            return
        ## the message is for us, ack it
        self.conn.ack({'message-id': headers['message-id']})
        host = message['host']
        if message['m_type'] == 'bad_token':
            logging.debug('Ooops, we sent a bad token, retrying')
            ctrl_queue = '/queue/ctrl_%s' % host
            self.hosts[host] = 'wait_for_token'
            self.conn.subscribe(destination=ctrl_queue, ack='client')
            return
        self.results[host] = message
        del self.hosts[host]
        logging.info('[%d|%d|%d]'
                     % (len(self.results),
                        len(self.hosts),
                        len(self.hosts) + len(self.results)))
        if not self.hosts:
            self.finished = True
            self.conn.disconnect()

    def on_message(self, headers, message):
        if headers['destination'].startswith('/queue/ctrl_'):
            self.handle_token(headers, message)
        else:
            self.handle_result(headers, message)
