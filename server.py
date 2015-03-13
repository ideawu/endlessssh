# coding=UTF-8
"""
@author: ideawu@163.com
@link: http://www.ideawu.net/
Proxy Server.
"""
import socket
import select
import sys, time
import thread
import random
from ctypes import c_uint, c_int
from tunnel import *
from stdio import *
import server_conf as config


if len(sys.argv) > 1 and sys.argv[1] == '-h':
	print """
Usage:
	python %s [port]
	port: port number Proxy Server listen for connections, default 8888
Example:
	python %s
	OR
	python %s 8889
	""" % (sys.argv[0], sys.argv[0], sys.argv[0])
	sys.exit(0)


quit = False


HOST = '0.0.0.0'
if len(sys.argv) > 1:
	PORT = int(sys.argv[1])
else:
	PORT = 8888
serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
serv.bind((HOST, PORT))
serv.listen(5)
print 'Proxy Server listen on', HOST, PORT



class Session:
	def __init__(self):
		self.id = None
		self._authed = False
		self.status = 'closed' # connected|disconnected|closed

		self.tunnel = Tunnel()
		self.tunnel.ptr = self

		self.app = None

	def auth(self):
		self._authed = True

	def unauth(self):
		self._authed = False

	def authed(self):
		return self._authed

	def alive(self):
		return self.status == 'connected'

	def connect(self):
		self.status = 'connected'

	def disconnect(self):
		self.status = 'disconnected'
		if self.tunnel.alive():
			self.tunnel.close()

	def disconnected(self):
		self.status == 'disconnected'

	def recover(self, n_sess):
		self.id = n_sess.id
		self._authed = n_sess._authed
		self.app = n_sess.app
		self.tunnel.recover(n_sess.tunnel)



class Sessions(dict):
	def __init__(self):
		pass

	def new_session(self):
		sess = Session()
		sess.tunnel.on_recv_head = self.on_recv_head
		sess.tunnel.on_recv_data = self.on_recv_data

		while True:
			#sess.id = str(random.random())
			sess.id = str(random.randint(0, 100)) # TODO: 仅供测试
			if not self.has_key(sess.id):
				self[sess.id] = sess
				break
		return sess

	def del_session(self, sess_or_id):
		if sess_or_id.__class__.__name__ == Session.__name__:
			id = sess_or_id.id
		else:
			id = sess_or_id
		del self[id]
		print 'Del session %s, id: %s' % (sess.tunnel.addr, id)

	def on_recv_head(self, tunnel, packet):
		print 'tunnel recv header:', repr(packet.head)

		sess = tunnel.ptr
		# 处理策略: 安静地失败, 不要回复告知原因. 让客户端自己超时

		if packet.type == 'login':
			resp = Packet()
			resp.type = 'login'
			resp.cookie = sess.id
			tunnel.send_packet(resp)

			sess.auth()
			print 'Session %s logged in' % sess.id

		elif packet.type == 'recover':
			sid = packet.cookie
			n_sess = self.get(sid)
			if n_sess == None:
				print 'Recover failed, cookie not found: %s' % sid
				return -1

			ack = packet.last_ack_sent
			#print 'recover ack: %d - %d' % (n_sess.tunnel.snd_una.value, ack.value)
			if n_sess.tunnel.bad_ack(ack):
				print 'bad ack: %d, expect: [%d, %d]' % (ack.value, n_sess.tunnel.snd_una.value, n_sess.tunnel.snd_nxt.value)
				return -1
			n_sess.tunnel.handle_ack(ack)

			resp = Packet()
			resp.type = 'recover'
			resp.cookie = n_sess.id
			resp.set_header('last_ack_sent', n_sess.tunnel.rcv_nxt.value)

			sess.tunnel.send_packet(resp)
			sess.tunnel.proc_send() # 立即发送

			del self[sess.id]
			del self[n_sess.id]

			###########
			sess.recover(n_sess)

			self[sess.id] = sess
			print 'Session %s recovered' % sess.id
		elif packet.type == 'logout':
			print 'receive logout packet'
			if sess.authed():
				sess.unauth()
				sess.tunnel.close()
				sessions.del_session(sess)
			return -1
		elif packet.type == 'proxy':
			host, port = packet.get_header('connect').split(':', 1)
			port = int(port)

			app = App()
			app.connect(host, port)
			print 'app connect to %s:%d' % (host, port)
			app.sess = sess
			sess.app = app

	def on_recv_data(self, tunnel, data):
		#print 'tunnel recv:', repr(data)
		sess = tunnel.ptr
		if sess.app:
			sess.app.send(data)
		#else:
		#	print 'sess.app None'


class App:
	def __init__(self):
		self.sess = None
		self.sock = None
		self.send_str = ''

	def fileno(self):
		return self.sock.fileno()

	def connect(self, host, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((host, port))
		self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

	def close(self):
		self.sock.close()

	def send(self, data):
		self.send_str += data

	def recv(self):
		try:
			return self.sock.recv(128*8192)
		except:
			return ''

	def proc_send(self):
		try:
			ret = self.sock.send(self.send_str)
			self.send_str = self.send_str[ret : ]
			return ret
		except:
			return -1

def proc_stdin():
	line = stdio.readline()
	cmd = line.strip().lower()
	if cmd == 'quit' or cmd == 'q':
		print 'quit...'
		globals()['quit'] = True
	if cmd == 'c':
		print 'manualy close disconnect tunnel'
		for i, sess in sessions.iteritems():
			if sess.authed():
				print 'disconnect', sess.id
				sess.disconnect()



sessions = Sessions()

while not quit:
	# TODO: 处理会话超时

	# TODO: 更好的方式
	rfds = {}
	wfds = {}
	rfds[serv.fileno()] = ('server', serv)
	rfds[stdio.STDIN_FILENO] = ('stdio', None)
	for k, sess in sessions.iteritems():
		if sess.alive():
			rfds[sess.tunnel.fileno()] = ('tunnel', sess)
			if sess.tunnel.has_data_to_send():
				wfds[sess.tunnel.fileno()] = ('tunnel', sess)
			if sess.app:
				rfds[sess.app.fileno()] = ('app', sess)
				if sess.app.send_str:
					wfds[sess.app.fileno()] = ('app', sess)

	#print rfds.keys(), wfds.keys()
	i,o,e = select.select(rfds.keys(), wfds.keys(), [], 1)
	#print i, o, e

	# TODO: 如果 send 失败, 还需要 recv 吗?

	for fd in o:
		type, sess = wfds[fd]
		if type == 'tunnel':
			if sess.tunnel.proc_send() == -1:
				print 'tunnel.proc_send error'
		elif type == 'app':
			if sess.app.proc_send() == -1:
				print 'app.proc_send error'

	for fd in i:
		type, sess = rfds[fd]

		if type == 'stdio':
			proc_stdin()
		elif type == 'server':
			sock, addr = serv.accept()
			# TODO: check allow ip table
			if (addr[0] not in config.hosts['allow']) or (addr[0] in config.hosts['deny']):
				print 'Deny connection from ', addr[0]
				sock.close()
			else:
				sess = sessions.new_session()
				sess.connect()
				sess.tunnel.accept(sock)
				print 'New session from %s, id: %s' % (sess.tunnel.addr, sess.id)
		elif type == 'tunnel':
			if sess.tunnel.proc_recv() == -1:
				sess.disconnect()
				if sess.authed():
					print 'Disconnect session %s, id: %s' % (sess.tunnel.addr, sess.id)
				else:
					sessions.del_session(sess)
		elif type == 'app':
			data = sess.app.recv()
			if not data:
				print 'app recv error'
				print 'Del session %s, id: %s' % (sess.tunnel.addr, sess.id)
				sess.tunnel.close()
				sessions.del_session(sess)
			else:
				#print 'app recv:', repr(data)
				#print 'app recv:', len(data)
				sess.tunnel.send(data)

serv.close()
for sess in sessions.values():
	if sess.alive():
		sess.disconnect()
		if sess.app:
			sess.app.close()

