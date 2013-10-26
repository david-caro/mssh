#!/usr/bin/env python
#encoding: utf-8

import os
import logging
import time
import json
import socket
import subprocess
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import (
    PKCS1_OAEP,
    AES,
)
from Crypto.Signature import PKCS1_PSS
from Crypto.Hash.SHA import SHA1Hash
import base64
import copy
from traceback import format_exc


HOSTNAME = socket.getfqdn()
AES_SIZE = 16
PADDING_BYTE = '0'


############ Encription helpers ######################
def pad(msg):
    msg = msg.encode('utf-8')
    return msg + (AES_SIZE - len(msg) % AES_SIZE) * PADDING_BYTE


def unpad(msg):
    while msg[-1] == PADDING_BYTE:
        msg = msg[:-1]
    return msg


def verifyRSA(msg, key, signature):
    msg_hash = SHA1Hash(msg)
    cipher = PKCS1_PSS.new(key)
    return cipher.verify(msg_hash, base64.b64decode(signature)) and msg


def signRSA(msg, key):
    msg_hash = SHA1Hash(msg)
    cipher = PKCS1_PSS.new(key)
    return base64.b64encode(cipher.sign(msg_hash))


def encryptRSA(msg, key):
    cipher = PKCS1_OAEP.new(key)
    return base64.b64encode(cipher.encrypt(msg))


def encryptAES(msg, key):
    cipher = AES.new(key)
    return base64.b64encode(cipher.encrypt(msg))


def decryptRSA(msg, key):
    cipher = PKCS1_OAEP.new(key)
    return cipher.decrypt(base64.b64decode(msg))


def decryptAES(msg, key):
    cipher = AES.new(key)
    return cipher.decrypt(base64.b64decode(msg))


def wrap(dict_obj, key):
    logging.debug('Wrapping: %r' % dict_obj)
    payload = json.dumps(dict_obj)
    aes_key = os.urandom(AES_SIZE)
    res = {}
    res['payload'] = encryptAES(pad(payload), aes_key)
    res['key'] = encryptRSA(aes_key, key)
    logging.debug('Wrapped: %r' % res)
    return res


def unwrap(dict_obj, key):
    logging.debug('Unwrapping %s' % dict_obj)
    aes_key = decryptRSA(dict_obj['key'], key)
    payload = decryptAES(dict_obj['payload'], aes_key)
    res = json.loads(unpad(payload))
    logging.debug('Unwrapped: %s' % res)
    return res


#### Messages and related classes ####################
class MalformedMessage(Exception):
    pass


class Message(dict):
    def __init__(self, m_type, token, priv_key, pub_key, **kwargs):
        self['token'] = token
        self['m_type'] = m_type
        self.priv_key = priv_key
        self.pub_key = pub_key

    def __str__(self):
        signed_message = {}
        signed_message['data'] = json.dumps(self)
        signed_message['signature'] = signRSA(signed_message['data'],
                                              self.priv_key)
        signed_message['host'] = HOSTNAME
        signed_message['pub_key'] = \
            self.priv_key.publickey().exportKey(format='OpenSSH')
        logging.debug("Wrapping message with key %s"
                      % self.pub_key.exportKey(format='OpenSSH'))
        return json.dumps(wrap(signed_message, self.pub_key))

    @classmethod
    def from_str(cls, msg_str, priv_key=None, **kwargs):
        try:
            msg_dict = json.loads(msg_str)
            if priv_key:
                unwrapped_msg_dict = unwrap(msg_dict, priv_key)
            else:
                unwrapped_msg_dict = msg_dict
            ## TODO: verify the sent pub_key
            pub_key = RSA.importKey(unwrapped_msg_dict['pub_key'])
            signature = unwrapped_msg_dict['signature']
            if not verifyRSA(str(unwrapped_msg_dict['data']),
                             pub_key,
                             signature):
                raise ValueError('Wrong signature')
            kwargs.update(json.loads(unwrapped_msg_dict['data']))
            kwargs['pub_key'] = pub_key
            kwargs['priv_key'] = priv_key
            print kwargs
            return cls(**kwargs)
        except (ValueError, TypeError) as exc:
            raise MalformedMessage('%s\n%s' % (msg_str, format_exc(exc)))


class Token(dict):
    def __init__(self, pub_key, token=None, **kwargs):
        if isinstance(pub_key, unicode):
            pub_key = RSA.importKey(pub_key)
        self.key = pub_key
        self['pub_key'] = pub_key.publickey().exportKey(format='OpenSSH')
        self['token'] = token \
            and verifyRSA(token, pub_key, kwargs['signature']) \
            or self.generate_token()
        self['m_type'] = 'token'
        self['host'] = kwargs.get('host', HOSTNAME)

    @staticmethod
    def generate_token():
        rand = str(random.randint(0, 9999))
        ts = repr(time.time()).replace('.', '')
        return rand + ts

    def __str__(self):
        new_token = copy.deepcopy(self)
        new_token['signature'] = signRSA(new_token['token'], self.key)
        return json.dumps(new_token)

    @classmethod
    def from_str(cls, msg_str, **kwargs):
        try:
            msg_dict = json.loads(msg_str)
            kwargs.update(msg_dict)
            return cls(**kwargs)
        except (ValueError, TypeError) as exc:
            raise MalformedMessage('%s\n%s' % (msg_str, format_exc(exc)))


class BadToken(Message):
    def __init__(self, token, priv_key, pub_key, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(BadToken, self).__init__('bad_token', token,
                                       priv_key, pub_key, **kwargs)
        self['m_type'] = 'bad_token'
        self['host'] = HOSTNAME


class CommandRequest(Message):
    def __init__(self, token, priv_key, pub_key, command,
                 return_queue, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(CommandRequest, self).__init__('command_request', token,
                                             priv_key, pub_key, **kwargs)
        self['command'] = command
        self['return_queue'] = return_queue
        self['m_type'] = 'command_request'


class CommandResult(Message):
    def __init__(self, token, priv_key, pub_key, command, return_queue,
                 rc='', stdout='', stderr='', host=HOSTNAME, **kwargs):
        if 'm_type' in kwargs:
            kwargs.pop('m_type')
        super(CommandResult, self).__init__('command_result', token,
                                            priv_key, pub_key, **kwargs)
        self['token'] = token
        self['command'] = command
        self['return_queue'] = return_queue
        self['rc'] = rc
        self['stdout'] = stdout
        self['stderr'] = stderr
        self['host'] = host
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

    @classmethod
    def from_cmd_req(cls, cmd_req):
        priv_key = cmd_req.priv_key
        pub_key = cmd_req.pub_key
        return cls(priv_key=priv_key, pub_key=pub_key, **cmd_req)


MSG_TYPES = {
    'command_result': CommandResult,
    'command_request': CommandRequest,
    'token': Token,
    'bad_token': BadToken,
}


def to_message(str_msg, priv_key, pub_keys=None):
    try:
        str_msg = unwrap(json.loads(str_msg), priv_key)
        if not pub_keys:
            ## TODO: verify pub_key
            pub_key = RSA.importKey(str_msg['pub_key'])
        else:
            pub_key = pub_keys[str_msg['host']]
        signature = str_msg['signature']
        if not verifyRSA(str_msg['data'], pub_key, signature):
            raise ValueError('Wrong signature')
        msg = json.loads(str_msg['data'])
        msg['pub_key'] = pub_key
        msg['priv_key'] = priv_key
        return MSG_TYPES[msg['m_type']](**msg)
    except ValueError as exc:
        raise MalformedMessage('Unable to parse json: %s\n%s'
                               % (str_msg, format_exc(exc)))
    except KeyError as exc:
        raise MalformedMessage('Unknown message type: %s\n%s'
                               % (str_msg, format_exc(exc)))
    except TypeError as exc:
        raise MalformedMessage('Missing or duplicate fields: %s\n%s'
                               % (str_msg, format_exc(exc)))


######## Helper methods and classes #########################
class CommandPool(object):
    def __init__(self, conn, key, max_procs=2):
        self.max_procs = 2
        self.pool = {}
        self.conn = conn
        self.key = key
        self.init_poll()

    def init_poll(self):
        for _ in range(self.max_procs):
            new_token = Token(pub_key=self.key)
            self.pool[new_token['token']] = None
            self.send_token(new_token)

    def send_token(self, token):
            self.send_msg(token, '/queue/ctrl_%s' % HOSTNAME)

    def send_bad_token(self, token, cmd_req):
        bad_token = BadToken(
            token,
            priv_key=self.key,
            pub_key=cmd_req.pub_key)
        self.send_msg(bad_token, cmd_req['return_queue'])

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
            new_token = Token(pub_key=self.key)
            self.pool[new_token['token']] = None
            self.send_token(new_token)

    def add_command(self, cmd_req):
        token = cmd_req['token']
        if token in self.pool and not self.pool[token]:
            cmd_res = CommandResult.from_cmd_req(cmd_req)
            cmd_res.run()
            logging.debug('Running command "%s"' % cmd_res['command'])
            self.pool[token] = cmd_res
        elif token not in self.pool:
            logging.warn("Received a bad token: %r" % cmd_req)
            self.send_bad_token(token, cmd_req)

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
            if results[host]['rc']:
                print "%s::error" % host
            else:
                print "%s::ok" % host
        else:
            print "%s::error::timeout" % host
    return global_rc


######### Listener classes ###############################
class BaseListener():
    def load_keys(self, key_path):
        if key_path is None:
            key_path = os.path.expanduser('~/.ssh/id_rsa')
        if not os.path.exists(key_path):
            raise Exception('Unable to lad key %s, file not found' % key_path)
        self.key = RSA.importKey(open(key_path))

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
    def __init__(self, server, port, conn, key_path=None, max_procs=2):
        self.server = server
        self.port = port
        self.conn = conn
        self.tokens = []

        self.load_keys(key_path)
        self.start_conn()
        self.pool = CommandPool(
            conn=conn,
            max_procs=max_procs,
            key=self.key)
        in_queue = '/queue/in_%s' % HOSTNAME
        self.conn.subscribe(destination=in_queue, ack='auto')

    def poll(self):
        self.pool.poll()

    def on_message(self, headers, message):
        logging.info("Got command: %s" % message)
        try:
            cmd_req = to_message(message, self.key)
        except MalformedMessage as exc:
            logging.error('Unalbe to process command %s: %s'
                          % (message, format_exc(exc)))
            return
        self.pool.add_command(cmd_req)


class ClientListener(BaseListener):
    def __init__(self, server, port, command, conn, hosts, key_path=None):
        self.server = server
        self.port = port
        self.conn = conn
        self.return_queue = '/queue/return_%s' % HOSTNAME
        self.command = command
        self.pub_keys = {}

        self.load_keys(key_path)
        self.hosts = dict((h, None) for h in hosts)
        self.results = {}
        self.start_conn()
        self.subscribe_for_tokens()
        self.finished = False
        self.listening = False

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
        token_msg = Token.from_str(message, key=self.key)
        logging.info("::%s::Got token: %s, sending command"
                     % (host, token_msg['token']))
        self.pub_keys[host] = RSA.importKey(token_msg['pub_key'])
        command = CommandRequest(command=self.command,
                                 token=token_msg['token'],
                                 priv_key=self.key,
                                 pub_key=self.pub_keys[host],
                                 return_queue=self.return_queue)
        in_queue = '/queue/in_%s' % host
        self.conn.send(str(command), destination=in_queue)
        self.conn.ack({'message-id': headers['message-id']})
        self.conn.unsubscribe(destination='/queue/ctrl_%s' % host)
        if not self.listening:
            self.listening = True
            self.conn.subscribe(destination=self.return_queue,
                                ack='client-individual')
        logging.debug('::%s::Command sent, waiting for response' % host)
        self.hosts[host] = token_msg['token']

    def handle_result(self, headers, message):
        logging.info('Got response %s' % message)
        try:
            message = to_message(message, self.key, self.pub_keys)
        except MalformedMessage as exc:
            logging.warn('Unable to parse response %s: %s'
                         % (message, format_exc(exc)))
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
