#!/usr/bin/env python
# -*- coding: utf-8 -*-


import paramiko


class SSHCopier:
    """Copy files via SSH

    :param hostname='127.0.0.1',
    :param port=22,
    :param username='user',
    :param password='password',
    :param rsa_private_key_filename='~/.ssh/rsa_private_key',
    :param dir_remote='/home/to',
    :param files_to_copy=[],
    :param dry=False
    """

    # remote SSH server hostname
    hostname = None

    # remote SSH server port
    port = None

    # remote SSH username
    username = None

    # remote SSH password
    password = None

    # local path to private RSA key, typically ~/.ssh/rsa_key_for_remote_host
    rsa_private_key_filename = None

    # dir on remote SSH server where files would be copied
    dir_remote = None

    # list of files to copy
    files_to_copy = None

    def __init__(
            self,
            hostname='127.0.0.1',
            port=22,
            username='user',
            password='password',
            rsa_private_key_filename='~/.ssh/rsa_private_key',
            dir_remote='/home/to',
            files_to_copy=[],
            dry=False
    ):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.rsa_private_key_filename = rsa_private_key_filename
        self.dir_remote = dir_remote
        self.files_to_copy = files_to_copy
        self.dry = dry

    def copy_files_list(self):
        """Copy list of files

        At first try to connect using a private key either from a private key file
        or provided by an SSH agent.
        If RSA authentication fails, then make second attempt
        with password login.
        """

        # get host key, if we know one
        hostkeytype = None
        hostkey = None
        files_copied = 0

        if self.dry:
            # just print what we'd like to do in here
            # do actions would be taken
            for file in self.files_to_copy:
                print("DRY: copy %(file)s to %(hostname)s:%(port)s/%(dir)s as %(username)s:%(password)s" % {
                    'file': file,
                    'hostname': self.hostname,
                    'port': self.port,
                    'dir': self.dir_remote,
                    'username': self.username,
                    'password': '***'
                })
            # no actual actions would be taken - nothing to do in this method any more
            return

        # build dictionary of known hosts
        try:
            host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        except:
            # can't open known_hosts file, assume it's empty
            host_keys = {}

        if self.hostname in host_keys:
            # already known host
            hostkeytype = host_keys[self.hostname].keys()[0]
            hostkey = host_keys[self.hostname][hostkeytype]
            print('Using host key of type ' + hostkeytype)

        # connect
        try:
            print('Establishing SSH connection to:', self.hostname, self.port, '...')
            transport = paramiko.Transport((self.hostname, self.port))
            transport.start_client()
        except:
            # unable to connect at all
            return

        # key auth
        # try to authenticate with any of:
        # 1. private keys available from SSH agent
        # 2. local private RSA key file (assumes no pass phrase required)

        # load available keys
        rsa_keys = paramiko.Agent().get_keys()

        # append key from provided key file to other available keys
        try:
            key = paramiko.RSAKey.from_private_key_file(self.rsa_private_key_filename)
            rsa_keys += (key,)
        except:
            print('Failed loading RSA private key', self.rsa_private_key_filename)

        if len(rsa_keys) > 0:
            # have RSA keys, try to auth with all of them
            for key in rsa_keys:
                try:
                    transport.auth_publickey(self.username, key)
                    # auth succeeded with this key
                    # not need to continue with next key
                    break
                except:
                    # auth failed with this key, continue with next key
                    pass

        if not transport.is_authenticated():
            # key auth not performed or failed - try username/password
            transport.auth_password(username=self.username, password=self.password)
        else:
            # key auth completed successfully
            sftp = transport.open_session()

        sftp = paramiko.SFTPClient.from_transport(transport)

        # create remote dir
        try:
            sftp.mkdir(self.dir_remote)
        except:
            # may be remote dir already exists
            pass

        # copy files
        for filename in self.files_to_copy:
            remote_filepath = self.dir_remote + '/' + os.path.basename(filename)
            try:
                sftp.put(filename, remote_filepath)
                files_copied += 1
            except:
                # file not copied, skip so far
                pass

        sftp.close()
        transport.close()

        return files_copied
