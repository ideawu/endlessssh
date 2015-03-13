# endlessssh

__Tunneling SSH over HTTP__

endlessssh(all characters in lower case), is a tool written in Python, includes an SSH ProxyCommand and a ProxyServer. It gives you a chance to keep a ssh session never break, even if you move you computer(ssh client runs on) from office to home.

endlessssh use a protocol that looks like HTTP to tunnelling SSH. In future, the protocol will be imporved to work more like HTTP, as to use SSH when the firewall forbids SSH - as long as the firewall doesn't forbid HTTP.

### Usage:

1. Proxy Server usally runs on the same machine on which sshd(SSH server) is running. Edit server_conf.py, add the IP address of ssh_proxy to host['allow'] list, the run:

	```python server.py 8888```

2. SSH client, connect to sshd

	```ssh -o "ProxyCommand python ssh_proxy.py sshd_host 8888 %h %p" user@sshd_host```

工具有两个特点:

1. Tunneling SSH over REAL HTTP(完善中)

	让 SSH 工作在 HTTP 协议上, 从而穿越防火墙.

2. 持续的会话

	即使 TCP 网络连接断开(这时, SSH 会话会失效), SSH 会话仍然保持, 直到网络重连后, 会话继续. 