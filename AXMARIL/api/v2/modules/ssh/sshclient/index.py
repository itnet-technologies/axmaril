import paramiko
from threading import Thread
from io import StringIO

class SSHClient:
    def __init__(self, ws, host, port, username, password = None, private_key_string = None):
        self.ws = ws
        self.ssh = paramiko.SSHClient()
        if private_key_string is not None:
            self.ssh.load_system_host_keys()
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            # private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
            private_key_file = StringIO(private_key_string)
            private_key = paramiko.RSAKey.from_private_key(private_key_file)
            self.ssh.connect(host, port, username, pkey=private_key)
        else:
            self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self.ssh.connect(host, port, username, password)
        self.channel = self.ssh.invoke_shell()
        print(f"Connected to {host}:{port} as {username}")

    def start(self):
        Thread(target=self._forward_inbound).start()

    def _forward_inbound(self):
        while True:
            if self.channel.recv_ready():
                data = self.channel.recv(1024).decode('utf-8')
                print(f"Received from SSH: {data}")
                self.ws.send(data)

    def send(self, message):
        print(f"Sending to SSH: {message}")
        if self.channel.send_ready():
            self.channel.send(message + '\n')  # Ensure command is sent with newline
    
    def disconnect(self, username):
        self.ssh.exec_command('skill -kill -u {}'.format(username))