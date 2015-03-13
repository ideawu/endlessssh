# coding=UTF-8
"""
@author: ideawu@163.com
@link: http://www.ideawu.net/
"""
import socket
import copy
from ctypes import c_uint, c_int


# TODO: 可以不做类型转换来判断, 因为类型转换损耗
def SEQ_LT(a, b):
	return c_int(a.value - b.value).value < 0
def SEQ_LE(a, b):
	return c_int(a.value - b.value).value <= 0
def SEQ_GT(a, b):
	return c_int(a.value - b.value).value > 0
def SEQ_GE(a, b):
	return c_int(a.value - b.value).value >= 0


# TODO: 重新组织字段
class Packet:
	def __init__(self):
		self.seq = c_uint(0)
		self.ack = c_uint(0)
		self.last_ack_sent = c_uint(0)
		self.head_ex = {}
		self.reset()

	def reset(self):
		self.type = None
		self.len = 0
		self.seq.value = 0
		self.ack.value = 0
		self.last_ack_sent.value = 0
		self.cookie = None

		self.head_ex.clear()

		self.head = ''
		self.body = ''

		self.head_sent = 0 # 首部已经发送出去的字节数
		self.body_sent = 0 # 这两个变量放到 Tunnel 中?

	def set_header(self, k, v):
		v = str(v)
		if k == 'type':
			self.type = v
		elif k == 'seq':
			if v.isdigit():
				self.seq.value = int(v)
		elif k == 'ack':
			if v.isdigit():
				self.ack.value = int(v)
		elif k == 'len' or k == 'Content-Length':
			if v.isdigit():
				self.len = int(v)
		elif k == 'Cookie':
			self.cookie = v
		elif k == 'last_ack_sent':
			if v.isdigit():
				self.last_ack_sent = c_uint(int(v))
		self.head_ex[k] = v

	def has_key(self, k):
		return self.head_ex.has_key(k)

	def get_header(self, k):
		return self.head_ex.get(k)

	def append(self, data):
		self.body += data
		self.len = len(self.body)

	# 序列化之后, 首部和报体分别保存
	def encode_head(self):
		self.head = ''
		self.head += 'POST /%s/%d/%d HTTP/1.1\r\n' % (self.type, self.seq.value, self.ack.value)
		self.head += 'Content-Length:' + str(self.len) + '\r\n'
		if self.cookie:
			self.head += 'Cookie:' + str(self.cookie) + '\r\n'
		#self.head += 'type:' + str(self.type) + '\r\n'
		#self.head += 'seq:' + str(self.seq.value) + '\r\n'
		#self.head += 'ack:' + str(self.ack.value) + '\r\n'
		#self.head += 'len:' + str(self.len) + '\r\n'
		for k,v in self.head_ex.iteritems():
			self.head += str(k) + ':' + str(v) + '\r\n'
		self.head += '\r\n'

	def decode_head(self):
		lines = self.head.splitlines()
		line = lines[0]
		del lines[0]
		ps = line.split(None, 2)
		if len(ps) == 3:
			ps = ps[1].split('/', 3)
			if len(ps) == 4:
				self.set_header('type', ps[1])
				self.set_header('seq', ps[2])
				self.set_header('ack', ps[3])

		for line in lines:
			line = line.strip()
			if line.find(':') == -1:
				#print 'ignore not key-value header line: ', repr(line)
				continue
			else:
				key, val = line.split(':', 1)
				key = key.strip()
				val = val.strip()
				self.set_header(key, val)

class Tunnel:
	def __init__(self):
		self.id = None
		self.ptr = None
		# TODO: 需要更好的状态定义
		self.status = 'alive' # alive|disconnected
		self.MIN_PACKET_SIZE = 512 # 最小的数据报文字节数
		self.MAX_PACKET_SIZE = 128 * 1024
		self.MAX_HEADER_SIZE = 8 * 1024

		self.sock = None
		self.addr = ''

		self.recv_packet = Packet()

		self.recv_status = 'head' # head | body
		self.send_status = 'head' # head | body

		self.recv_str = ''
		self.send_buf = []
		self.data_sent = '' # 等待 ack 的已发送数据

		SEQ_START = 0
		self.rcv_nxt = c_uint(SEQ_START)
		self.snd_nxt = c_uint(SEQ_START)
		self.snd_una = c_uint(SEQ_START)
		self.last_ack_sent = c_uint(SEQ_START)

		self.recv_head_len = 0
		self.recv_body_left = 0

		self.on_recv_head = None # 报头处理函数(Tunnel, Packet)
		self.on_recv_data = None # 数据处理函数

	def alive(self):
		return self.status == 'alive'

	def disconnect(self):
		self.status = 'disconnected'

	def fileno(self):
		return self.sock.fileno()

	def connect(self, host, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.connect((host, port))
		self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		self.addr = "%s:%d" % (host, port)

	def accept(self, sock):
		self.sock = sock
		self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
		self.addr = "%s:%d" % self.sock.getsockname()

	def close(self):
		try:
			self.sock.close()
		except:
			pass

	def flush(self):
		while self.send_buf:
			p = self.send_buf[0]
			# 报文还存在空洞
			space = p.len - p.body_sent - len(p.body)
			if space > 0:
				break
			if self.proc_send() == -1:
				return -1

	def proxy(self, host, port):
		packet = Packet()
		packet.type = 'proxy'
		packet.set_header('connect', '%s:%d'%(host,port))
		self.send_packet(packet)
		self.flush()
		#print 'proxy to %s:%d'%(host,port)

	def print_seq(self):
		print 'snd_una: %d' % self.snd_una.value
		print 'snd_nxt: %d' % self.snd_nxt.value
		print 'rcv_nxt: %d' % self.rcv_nxt.value
		print 'last_ack_sent: %d' % self.last_ack_sent.value

	def bad_ack(self, ack):
		return SEQ_LT(ack, self.snd_una) or SEQ_GT(ack, self.snd_nxt)

	def bad_seq(self, seq):
		return seq.value != self.rcv_nxt.value

	def recover(self, tunnel):
		self.snd_una.value = tunnel.snd_una.value
		self.snd_nxt.value = tunnel.snd_nxt.value
		self.rcv_nxt.value = tunnel.rcv_nxt.value
		self.send_buf = copy.copy(tunnel.send_buf)

		self.data_sent = tunnel.data_sent

		# 如果报文已经发送了部分, 而把剩下的加入到待确认缓冲, 以便重传
		if len(self.send_buf) > 0:
			p = self.send_buf[0]
			if p.body_sent > 0:
				self.send_buf.pop(0)
				self.data_sent += p.body

		# 重传
		if len(self.data_sent) > 0:
			packet = Packet()
			packet.type = 'data'
			packet.seq.value = self.snd_una.value
			packet.append(self.data_sent)
			self.send_buf.insert(0, packet)

			#print 'retransmit', repr(self.data_sent)
			self.data_sent = ''

	def handle_ack(self, ack):
		# ack: next expected seq
		s_ack = ack.value - self.snd_una.value
		self.snd_una.value = ack.value
		self.data_sent = self.data_sent[s_ack : ]

	def has_data_to_send(self):
		# 对于发送报文, body只保存待发送的数据, 一旦发送, 数据将被删除
		if len(self.send_buf) > 0:
			p = self.send_buf[len(self.send_buf) - 1]
			if p.head_sent == 0 or (p.head_sent < len(p.head)) or p.body:
				return True
		return False

	def send(self, data):
		if len(self.send_buf) > 0:
			packet = self.send_buf[len(self.send_buf) - 1]
			if packet.type == 'data':
				# 如果还没开始发送报头, 则继续往该报文的报体添加数据
				if packet.head_sent == 0:
					space = self.MAX_PACKET_SIZE - len(packet.body)
					if space > 0:
						if len(data) <= space: # 扩包
							packet.body += data
							self.snd_nxt.value += len(data)
							if len(packet.body) > packet.len:
								packet.len = len(packet.body)
						else: # 分包
							left = data[0 : space]
							right = data[space :]

							packet.len = self.MAX_PACKET_SIZE
							packet.body += left
							self.snd_nxt.value += len(left)

							self._new_send_packet(right)
					return;
				else: # 分包
					# 如果报体数据不足, 则继续往该报文的报体添加数据
					space = packet.len - packet.body_sent - len(packet.body)
					if space > 0:
						if len(data) <= space: # 补充数据到报文中
							packet.body += data
							self.snd_nxt.value += len(data)
						else: # 分包
							left = data[0 : space]
							right = data[space:]

							packet.body += left
							self.snd_nxt.value += len(left)

							self._new_send_packet(right)
						return

		self._new_send_packet(data)

	def _new_send_packet(self, data):
		packet = Packet()
		packet.type = 'data'
		packet.seq.value = self.snd_nxt.value

		packet.append(data)
		self.snd_nxt.value += len(data)

		if packet.len < self.MIN_PACKET_SIZE:
			packet.len = self.MIN_PACKET_SIZE

		self.send_buf.append(packet)

	def send_packet(self, packet):
		if packet.len > self.MAX_PACKET_SIZE:
			return -1
		packet.seq.value = self.snd_nxt.value
		self.snd_nxt.value += len(packet.body) # 不是 packet.len, 因为 packet 可能只包含头部
		self.send_buf.append(packet)

	def proc_recv(self):
		try:
			data = self.sock.recv(8192)
			#print 'proc_recv: ' + repr(data)
		except:
			return -1
		if not data:
			return -1

		self.recv_str += data
		if self._proc_recv() == -1:
			return -1
		return len(data)

	def header_valid(self):
		if self.recv_packet.type == None:
			print 'type required'
			return False
		if self.recv_packet.has_key('type') == False:
			print 'type required'
			return False
		if self.recv_packet.has_key('seq') == False:
			print 'seq required'
			return False
		if self.recv_packet.has_key('ack') == False:
			print 'ack required'
			return False
		seq = self.recv_packet.seq
		ack = self.recv_packet.ack
		s_len = self.recv_packet.len

		if self.bad_seq(seq):
			print 'bad seq: %d, expect: %d' % (seq.value, self.rcv_nxt.value)
			return False
		if self.bad_ack(ack):
			print 'bad ack: %d, expect: [%d, %d]' % (ack.value, self.snd_una.value, self.snd_nxt.value)
			return False
		return True

	def _proc_recv(self):
		while True:
			if len(self.recv_str) == 0:
				break;

			if self.recv_status == 'head':
				pos = self.recv_str.find('\r\n\r\n', self.recv_head_len)
				if pos == -1:
					self.recv_head_len = len(self.recv_str)
					if self.recv_head_len > self.MAX_HEADER_SIZE:
						print 'recv_head_len error:', self.recv_head_len
						return -1
					# 停止解析
					break;
				else:
					self.recv_head_len = pos + 4
					if self.recv_head_len > self.MAX_HEADER_SIZE:
						print 'recv_head_len error:', self.recv_head_len
						return -1

				self.recv_packet.head = self.recv_str[0 : self.recv_head_len]
				self.recv_str = self.recv_str[self.recv_head_len : ]

				self.recv_packet.decode_head()
				if self.header_valid() == False:
					print 'invalid header'
					return -1

				self.handle_ack(self.recv_packet.ack) # ACK

				# 调用报头处理回调函数
				if self.on_recv_head != None:
					if self.on_recv_head(self, self.recv_packet) == -1:
						return -1

				self.recv_head_len = 0
				self.recv_body_left = self.recv_packet.len

				# 空报文特殊处理
				if self.recv_packet.len == 0:
					# 继续解析下一个报头
					#print 'empty packet'
					self.recv_packet.reset()
					continue
				else:
					self.recv_status = 'body'

			if self.recv_status == 'body':
				if len(self.recv_str) > 0:
					if len(self.recv_str) > self.recv_body_left:
						data = self.recv_str[0 : self.recv_body_left]
						self.recv_str = self.recv_str[self.recv_body_left : ]
					else:
						data = self.recv_str
						self.recv_str = ''

					r_len = len(data)
					self.rcv_nxt.value += r_len
					self.recv_body_left -= r_len

					# 调用数据处理回调函数
					# 每读到一点 body, 便处理一点, 不用等到整个 body
					if self.on_recv_data != None:
						if self.on_recv_data(self, data) == -1:
							return -1
					if self.recv_body_left == 0:
						self.recv_status = 'head'
						self.recv_packet.reset()

				if self.recv_status == 'body':
					# 如果没有解析完报体, 停止解析
					break

		#self.print_seq()
		return 0

	def proc_send(self):
		if not self.send_buf:
			return -1

		n_sent = 0
		packet = self.send_buf[0]

		if self.send_status == 'head':
			if packet.head_sent == 0:
				packet.ack.value = self.rcv_nxt.value
				self.last_ack_sent.value = packet.ack.value
				packet.encode_head()
				#print 'proc_send header:', repr(packet.head)

			try:
				ret = self.sock.send(packet.head[packet.head_sent :])
			except Exception,e:
				print repr(e)
				return -1
			packet.head_sent += ret
			n_sent += ret

			if packet.head_sent == len(packet.head):
				# 特殊对待空报文
				if packet.len == 0:
					self.send_buf.pop(0)
				else:
					self.send_status = 'body'
		else:
			#if self.send_status == 'body':
			# 这里使用 else, 是因为 proc_send 中只能调用一次 socket.send, 第二次可能阻塞
			# 发送一个报文调用最少两次 send, 是否比把报文拼成一个字符串再最少调用一次 send 损耗大,
			# 还不得而知
			if packet.body:
				try:
					ret = self.sock.send(packet.body)
				except Exception,e:
					print repr(e)
					return -1

				sent = packet.body[0 : ret]
				# 清除body中已发送的数据, 因为body会不断增加到很大的长度
				# 当 MIN_PACKET_SIZE 很大时, 会出现内存问题
				packet.body = packet.body[ret :]

				# 加入到待确认缓冲
				self.data_sent += sent
				#print 'proc_send' + repr(sent)

				packet.body_sent += ret
				n_sent += ret
				if packet.body_sent == packet.len:
					self.send_buf.pop(0)
					self.send_status = 'head'

		#self.print_seq()
		return n_sent

