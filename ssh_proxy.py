# coding=UTF-8
"""
@author: ideawu@163.com
@link: http://www.ideawu.net/
SSH Proxy Client.
"""
import socket, sys, select, time, signal
from ctypes import c_uint, c_int
from stdio import stdio
from tunnel import *


if len(sys.argv) != 5:
	print """
Usage:
	ssh -o "ProxyCommand python %s proxy_server_host proxy_server_port %%h %%p" user@host
	proxy_server_host: hostname on which Proxy Server runs on
	proxy_server_port: TCP port number to connect to Proxy Server
	user: SSH user
	host: SSH host

Example:
	ssh -o "ProxyCommand python %s 127.0.0.1 8888 %%h %%p" work@192.168.200.128
	""" % (sys.argv[0], sys.argv[0])
	sys.exit(0)

def login(tunnel):
	packet = Packet()
	packet.type = 'login'
	tunnel.send_packet(packet)
	tunnel.flush()

def recover(tunnel):
	#print 'try to recover'
	nt = Tunnel()
	try:
		nt.connect(HOST, PORT)
	except:
		return None

	nt.on_recv_head = on_recv_head
	nt.on_recv_data = on_recv_data

	packet = Packet()
	packet.type = 'recover'
	packet.cookie = globals()['session_id']
	packet.set_header('last_ack_sent', tunnel.rcv_nxt.value)

	nt.send_packet(packet)
	nt.flush()
	return nt

def on_recv_head(tunnel, packet):
	#print 'recv_head', packet.head

	if packet.type == 'login':
		if packet.has_key('Cookie'):
			globals()['session_id'] = packet.cookie

	if packet.type == 'recover':
		if packet.has_key('last_ack_sent'):
			old_tunnel = globals()['tunnel']

			ack = packet.last_ack_sent
			if old_tunnel.bad_ack(ack):
				#print 'bad ack: %d, expect: [%d, %d]' % (ack.value, old_tunnel.snd_una.value, old_tunnel.snd_nxt.value)
				return -1

			# 先 handle_ack 再 recover, 因为 recover 函数中要重新组织报文
			old_tunnel.handle_ack(ack)
			tunnel.recover(old_tunnel)

			globals()['nt'] = None
			globals()['tunnel'] = tunnel


def on_recv_data(tunnel, data):
	#print 'on_recv_data: ' + repr(data)
	return stdio.write(data)

def proc_stdio(tunnel):
	data = stdio.read()
	#print 'stdio recv', len(data)
	if len(data) == 0:
		return -1
	tunnel.send(data)


"""
def sig_handler(signum, frame):
	globals()['quit'] = True

signal.signal(signal.SIGABRT, sig_handler)
signal.signal(signal.SIGINT, sig_handler)
signal.signal(signal.SIGHUP, sig_handler)
signal.signal(signal.SIGTERM, sig_handler)
signal.signal(signal.SIGPIPE, sig_handler)
"""


HOST = sys.argv[1]
PORT = int(sys.argv[2])
sshd_host = sys.argv[3]
sshd_port = int(sys.argv[4])

tunnel = Tunnel()
tunnel.connect(HOST, PORT)

tunnel.on_recv_head = on_recv_head
tunnel.on_recv_data = on_recv_data

login(tunnel)
tunnel.proxy(sshd_host, sshd_port)

quit = False
nt = None
session_id = ''
connect_retry = 0

while True:
	wfds = []
	if tunnel.alive() and tunnel.has_data_to_send():
		wfds.append(tunnel.fileno())
	if nt and nt.has_data_to_send():
		wfds.append(nt.fileno())

	rfds = []
	if not quit:
		if nt:
			rfds.append(nt.fileno())
		if tunnel.alive():
			rfds.append(tunnel.fileno())
			rfds.append(stdio.STDIN_FILENO)


	if rfds or wfds: # Windows 不支持空的 fdset
		try:
			i,o,e = select.select(rfds, wfds, [], 1)
		except:
			break
	else:
		time.sleep(1)
		i,o,e = [], [], []
	#print i, o, e

	if tunnel.alive() == False and nt == None:
		connect_retry += 1
		# 多次重试后失败
		if connect_retry > 60:
			sys.exit('Exceeds max retries, quit.')
		time.sleep(5)
		nt = recover(tunnel)
	else:
		connect_retry = 0

	# 让未发送的数据都发送出去
	if quit and not i and not o:
		break;

	for fd in o:
		if nt and fd == nt.fileno():
			if nt.proc_send() == -1:
				nt = None
		elif fd == tunnel.fileno():
			if tunnel.proc_send() == -1:
				quit = True

	for fd in i:
		if nt and fd == nt.fileno():
			if nt.proc_recv() == -1:
				nt = None
		elif fd == tunnel.fileno():
			if tunnel.proc_recv() == -1:
				tunnel.disconnect()
		elif fd == stdio.STDIN_FILENO:
			if proc_stdio(tunnel) == -1:
				quit = True

tunnel.close()

