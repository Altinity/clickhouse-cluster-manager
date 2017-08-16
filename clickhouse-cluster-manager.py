# https://gist.github.com/sloria/7001839

import lxml
from lxml import etree

import os
import paramiko

import argparse
import tempfile
import re

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

    # local path to private RSA key, typically ~/.ss/my_rsa_to_hostname
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
            for file in self.files_to_copy:
                print("DRY: copy %(file)s to %(hostname)s:%(port)s/%(dir)s as %(username)s:%(password)s" % {
                    'file': file,
                    'hostname': self.hostname,
                    'port': self.port,
                    'dir': self.dir_remote,
                    'username': self.username,
                    'password': '***'
                })
            # no actual actions are expected - nothing to do in here
            return

        # build dictionary of known hosts
        try:
            host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        except:
            # can't open known_hosts
            host_keys = {}

        if self.hostname in host_keys:
            # already known host
            hostkeytype = host_keys[self.hostname].keys()[0]
            hostkey = host_keys[self.hostname][hostkeytype]
            print('Using host key of type' + hostkeytype)

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
        # 1. private keys available from an SSH agent
        # 2. local private RSA key file (assumes no pass phrase).

        # load available keys
        rsa_keys = paramiko.Agent().get_keys()

        # append key from key file to other available keys
        try:
            key = paramiko.RSAKey.from_private_key_file(self.rsa_private_key_filename)
            rsa_keys += (key,)
        except:
            print('Failed loading RSA private key ' + self.rsa_private_key_filename + ' desc ')

        if len(rsa_keys) > 0:
            # have RSA keys
            for key in rsa_keys:
                try:
                    transport.auth_publickey(self.username, key)
                    # auth succeeded
                    # not need to continue with next key
                    break
                except:
                    # auth failed
                    pass

        if not transport.is_authenticated():
            # key auth not performed or failed
            transport.auth_password(username=self.username, password=self.password)
        else:
            # key auth completed successfully
            sftp = transport.open_session()

        sftp = paramiko.SFTPClient.from_transport(transport)

        # create remote dir
        try:
            sftp.mkdir(self.dir_remote)
        except:
            pass

        # copy files
        for filename in self.files_to_copy:
            remote_file = self.dir_remote + '/' + os.path.basename(filename)
            try:
                sftp.put(filename, remote_file)
                files_copied += 1
            except:
                pass

        sftp.close()
        transport.close()

        return files_copied


class CHConfigManager:
    """ClickHouse configuration manager

    :param config string configuration content
    """

    # string - XML configuration content
    config = None

    # options dict
    options = None

    def __init__(self, config, options):
        self.config = config
        self.options = options

    @staticmethod
    def is_element_comment(element):
        """Check whether specified element is an XML comment

        :param element: Element to check
        :return: bool
        """
        return isinstance(element, lxml.etree._Comment)

    def add_cluster(self, cluster_name):
        """Add new cluster to config
        :param cluster_name:
        :return:
        """
        def on_cluster_root(remote_servers_element):
            """
            Add new cluster to the root of cluster specification
            :param remote_servers_element:
            :return:
            """
            new_cluster_element = etree.Element(cluster_name)
            remote_servers_element.append(new_cluster_element)

        return self.walk_config(on_cluster_root=on_cluster_root)

    def add_shard(self, cluster_name):
        """
        Add new shard into cluster named cluster_name
        :param cluster_name:
        :return:
        """
        def on_cluster(cluster_element, cluster_element_index):
            if cluster_element.tag != cluster_name:
                return
            new_shard_element = etree.Element('shard')
            cluster_element.append(new_shard_element)

        return self.walk_config(on_cluster=on_cluster)

    def add_replica(self, cluster_name, shard_index, host, port):
        """
        Add new replica with host:port into cluster named cluster_name shard with index shard_index

        :param cluster_name:
        :param shard_index:
        :param host:
        :param port:
        :return:
        """
        def on_shard(cluster_element, cluster_element_index, shard_element, shard_element_index):
            if cluster_element.tag != cluster_name:
                return

            if shard_element_index != shard_index:
                return

            new_replica_element = etree.Element('replica')

            new_host_element = etree.Element('host')
            new_host_element.text = host
            new_port_element = etree.Element('port')
            new_port_element.text = port

            new_replica_element.append(new_host_element)
            new_replica_element.append(new_port_element)

            shard_element.append(new_replica_element)

        return self.walk_config(on_shard=on_shard)

    def delete_cluster(self, cluster_name):
        """
        Delete cluster from cluster specification

        :param cluster_name:
        :return:
        """
        def on_cluster(cluster_element, cluster_element_index):
            if cluster_element.tag != cluster_name:
                return
            cluster_element.getparent().remove(cluster_element)

        return self.walk_config(on_cluster=on_cluster)

    def delete_shard(self, cluster_name, shard_index):
        """
        Delete shard with specified index in specified cluster
        :param cluster_name:
        :param shard_index:
        :return:
        """
        def on_shard(cluster_element, cluster_element_index, shard_element, shard_element_index):
            if cluster_element.tag != cluster_name:
                return

            if shard_element_index != shard_index:
                return

            cluster_element.remove(shard_element)

        return self.walk_config(on_shard=on_shard)

    def delete_replica(self, cluster_name, shard_index, host, port):
        """
        Delete replica having host:port inside shard with specified index in specified cluster
        :param cluster_name:
        :param shard_index:
        :param host:
        :param port:
        :return:
        """
        def on_replica(cluster_element, cluster_element_index, shard_element, shard_element_index, replica_element, replica_element_index):
            if cluster_element.tag != cluster_name:
                return

            if shard_element_index != shard_index:
                return

            shard_element.remove(replica_element)

        return self.walk_config(on_replica=on_replica)

    def print(self):
        """
        Print cluster specification
        :return:
        """
        def on_cluster(cluster_element, cluster_element_index):
            """Callback on_cluster"""
            print()
            print(cluster_element.tag)
            pass

        def on_shard(cluster_element, cluster_element_index, shard_element, shard_element_index):
            """Callback on_shard"""
            print('  ' + shard_element.tag + '[' + str(shard_element_index) + ']')
            pass

        def on_replica(cluster_element, cluster_element_index, shard_element, shard_element_index, replica_element, replica_element_index):
            """Callback on_replica"""
            host_element = replica_element.find('host')
            port_element = replica_element.find('port')
            print("    " + replica_element.tag + '[' + str(replica_element_index) + "]|" + host_element.tag + ":" + host_element.text + ":" + port_element.tag + ":" + port_element.text + " path: " + cluster_element.tag + '/' + shard_element.tag + '[' + str(shard_element_index) + ']/' + replica_element.tag)
            pass

        return self.walk_config(on_cluster=on_cluster, on_shard=on_shard, on_replica=on_replica)

    def push(self):
        """
        Push configuration onto all replicas found in cluster specification
        :return:
        """
        def on_replica(cluster_element, cluster_element_index, shard_element, shard_element_index, replica_element, replica_element_index):
            """
            Callback on_replica
            Accumulate all replica specifications
            """
            # extract host:port from child tags of <replica>
            host_element = replica_element.find('host')
            port_element = replica_element.find('port')
            print("    " + replica_element.tag + '[' + str(replica_element_index) + "]|" + host_element.tag + ":" + host_element.text + ":" + port_element.tag + ":" + port_element.text + " path: " + cluster_element.tag + '/' + shard_element.tag + '[' + str(shard_element_index) + ']/' + replica_element.tag)
            host = host_element.text
            port = port_element.text
            # accumulate {host:HOST, port:9000} dict
            on_replica.hosts.append({'host': host, 'port':port})

        # accumulate all replica specifications
        on_replica.hosts = []
        self.walk_config(on_replica=on_replica)

        # save config to temp file
        fd, tempfile_path = tempfile.mkstemp()
        os.write(fd, self.config)
        os.close(fd)
        print("Save config as %(tmpfile)s" % {'tmpfile': tempfile_path})

        # walk over all replica specifications and SSH copy config onto it
        for replica in on_replica.hosts:
            # where config would be copied to
            host = replica['host']
            print("Pushing to:" + host)

            #
            # SSH copy config file to replica
            #

            # copy temp file
            copier = SSHCopier(
                hostname=host,
                username=self.options['ssh-user'],
                password=self.options['ssh-password'],
                dir_remote='/etc/clickhouse-server/',
                files_to_copy=[tempfile_path],
                dry=self.options['dry']
            )
            copier.copy_files_list()

        # remove temp file
        os.remove(tempfile_path)

    # lxml.etree._Element
    # def on_cluster(self, cluster_element):
    #     print("cluster: " + cluster_element.tag)
    #
    # def on_shard(self, cluster_element, shard_element):
    #     print("  shard: " + shard_element.tag + " path: " + cluster_element.tag + '/' + shard_element.tag)
    #
    # def on_replica(self, cluster_element, shard_element, replica_element):
    #     host_element = replica_element.find('host')
    #     port_element = replica_element.find('port')
    #     print("    replica: " + replica_element.tag + "|" + host_element.tag + ":" + host_element.text + ":" + port_element.tag + ":" + port_element.text + " path: " + cluster_element.tag + '/' + shard_element.tag + '/' + replica_element.tag)

    def walk_config(
            self,
            on_cluster_root=None,
            on_cluster=None,
            on_shard=None,
            on_replica=None
    ):
        """
        Walk over cluster configuration calling callback functions on-the-way

        :param on_cluster_root:
        :param on_cluster:
        :param on_shard:
        :param on_replica:
        :return:
        """
        try:
            # ElementTree object
            config_tree = etree.fromstring(self.config, etree.XMLParser(remove_blank_text=True, encoding="utf-8"))
        except IOError:
            # file is not readable
            print("IOError")
            return
        except etree.XMLSyntaxError:
            # file is readable, but has does not contain well-formed XML
            print("SyntaxError")
            return


        # config_root = config_tree.getroot()
        # '<remote_servers>'
        remote_servers_element = config_tree.find('remote_servers')

        if remote_servers_element is None:
            # no <remote_servers> tag available
            return

        if callable(on_cluster_root):
            on_cluster_root(remote_servers_element)

        # iterate over <remote_servers> children elements
        # each tag inside it would be name of the cluster. ex: <my_perfect_cluster></my_perfect_cluster>

        if not len(remote_servers_element):
            print("No clusters defined")

        cluster_element_index = 0

        # walk over clusters inside 'remote servers'
        for cluster_element in remote_servers_element:

            # skip comments
            if self.is_element_comment(cluster_element):
                continue

            # normal element - cluster name <my_cool_cluster>

            if callable(on_cluster):
                on_cluster(cluster_element, cluster_element_index)

            shard_element_index = 0

            # walk over shards inside cluster
            for shard_element in cluster_element:

                # skip comments
                if self.is_element_comment(shard_element):
                    continue
                # skip everything what is not <shard> tag
                if shard_element.tag != 'shard':
                    continue

                # normal element - <shard>
                if callable(on_shard):
                    on_shard(cluster_element, cluster_element_index, shard_element, shard_element_index)

                replica_element_index = 0

                # walk over replicas inside shard
                for replica_element in shard_element:

                    # skip comments
                    if self.is_element_comment(replica_element):
                        continue
                    # skip everything what is not <replica> tag
                    if replica_element.tag != 'replica':
                        continue

                    # normal element - <replica>
                    if callable(on_replica):
                        on_replica(cluster_element, cluster_element_index, shard_element, shard_element_index, replica_element, replica_element_index)

                    replica_element_index += 1

                shard_element_index += 1

            cluster_element_index += 1

        #         new_host_element = etree.Element('host')
        #         new_host_element.text = 'super-duper-host'
        #         new_port_element = etree.Element('port')
        #         new_port_element.text = '9001'
        #
        #         new_replica_element = etree.Element('replica')
        #         new_replica_element.append(new_host_element)
        #         new_replica_element.append(new_port_element)
        #
        #         shard_element.append(new_replica_element)
        #
        self.config = etree.tostring(config_tree, pretty_print=True)
        return self.config


class CHManager:
    """
    High-level class for managing CH cluster configuration
    """
    options = None
    config = None
    ch_config_manager = None

    def __init__(self):
        self.options = self.parse_options()

    @staticmethod
    def parse_options():
        """
        parse CLI options into options dict
        :return: dict
        """
        argparser = argparse.ArgumentParser(
            description='ClickHouse configuration manager',
            epilog='==============='
        )
        argparser.add_argument(
            '--interactive',
            action='store_true',
            help='Interactive mode'
        )
        argparser.add_argument(
            '--dry',
            action='store_true',
            help='Dry mode - do not do anyting that can harm. '
            'Config files will not be pushed/written/etc. Just simulate. '
            'Useful for debugging. '
        )
        argparser.add_argument(
            '--config-file',
            type=str,
            default='',
            help='Path to CH server config file to work with. Default - not specified'
        )
        argparser.add_argument(
            '--ssh-user',
            type=str,
            default='root',
            help='username to be used when pushing on servers'
        )
        argparser.add_argument(
            '--ssh-password',
            type=str,
            default='',
            help='password to be used when pushing on servers'
        )
        argparser.add_argument(
            '--ssh-port',
            type=str,
            default='22',
            help='port to be used when pushing on servers'
        )
        argparser.add_argument(
            '--config-folder',
            type=str,
            default='/etc/clickhouse-server/',
            help='Path to CH server config folder. Default value=/etc/clickhouse-server/'
        )
        argparser.add_argument(
            '--config.xml',
            type=str,
            default='config.xml',
            help='CH server config file. Default value=config.xml'
        )
        argparser.add_argument(
            '--user.xml',
            type=str,
            default='user.xml',
            help='CH server user file. Default value=user.xml'
        )
        args = argparser.parse_args()

        # build options
        return {
            'interactive': args.interactive,
            'config-file': args.config_file,
            'dry': args.dry,
            'ssh-user': args.ssh_user,
            'ssh-password': args.ssh_password,
            'ssh-port': args.ssh_port,
            'config-folder': os.path.abspath(args.config_folder),
            'config.xml': os.path.abspath(args.config_folder + '/' + getattr(args, 'config.xml')),
            'user.xml': os.path.abspath(args.config_folder + '/' + getattr(args, 'user.xml'))
        }

    def open_config(self):
        try:
            f = open(self.options['config.xml'], 'rb')
            self.config = f.read()
            f.close()
            return True
        except:
            return False

    def write_config(self):
        f = open('test.xml', 'wb')
        f.write(self.config)
        f.close()

    @staticmethod
    def cluster_path_parse(line):
        """
        Parse cluster-address line specification
        :param line:
        :return: dict
        """
        # /cluster/0/host:port
        # /cluster/shard0/host:port

        line = line.strip()

        if not line.startswith('/'):
            line = '/' + line

        try:
            parts = line.split('/')
        except:
            parts = []

        try:
            cluster = parts[1]
        except IndexError:
            cluster = None

        try:
            # would like to consume both ways
            # .../0/...
            # .../shard0/...
            # so strip all non-numbers in the list
            shard_index = int(re.sub('[^0-9]', '', parts[2]))
        except IndexError:
            shard_index = None

        try:
            host_port = parts[3]
            host_port = host_port.split(':')
            host = host_port[0]
            port = host_port[1]
        except IndexError:
            host = None
            port = None

        return {
            'cluster': cluster,
            'shard_index': shard_index,
            'host': host,
            'port': port
        }

    @staticmethod
    def cluster_path_print():
        print('/cluster1/shard0/host:port')
        pass

    def add_cluster(self):
        """High-level add cluster"""
        print("Add cluster")
        c = self.cluster_path_parse(input("Cluster name to add:"))
        print(c)
        self.config = self.ch_config_manager.add_cluster(c['cluster'])

    def add_shard(self):
        """High-level add shard"""
        print("Add shard")
        c = self.cluster_path_parse(input("Cluster name to add shard:"))
        print(c)
        self.config = self.ch_config_manager.add_shard(c['cluster'])

    def add_replica(self):
        """High-level add replica"""
        print("Add replica")
        self.cluster_path_print()
        c = self.cluster_path_parse(input("Cluster path for replica:"))
        print(c)
        self.config = self.ch_config_manager.add_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

    def delete_cluster(self):
        """High-level delete cluster"""
        print("Delete cluster")
        c = self.cluster_path_parse(input("Cluster name to delete:"))
        print(c)
        self.config = self.ch_config_manager.delete_cluster(c['cluster'])

    def delete_shard(self):
        """High-level delete shard"""
        print("Delete shard")
        c = self.cluster_path_parse(input("Cluster path for shard:"))
        print(c)
        self.config = self.ch_config_manager.delete_shard(c['cluster'], c['shard_index'])

    def delete_replica(self):
        """High-level delete replica"""
        print("Delete replica")
        self.cluster_path_print()
        c = self.cluster_path_parse(input("Cluster path for replica:"))
        print(c)
        self.config = self.ch_config_manager.delete_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

    def print(self):
        """High-level print config"""
        print("Print cluster layout")
        self.ch_config_manager.print()

    def write(self):
        """High-level write config"""
        print("Write cluster layout to disk")
        self.write_config()

    def push(self):
        """High-level push config"""
        self.ch_config_manager.push()
        print("pUsh config everywhere")

    @staticmethod
    def get_interactive_choice():
        print()
        print("[1] Add cluster")
        print("[2] Add shard")
        print("[3] Add replica")
        print()
        print("[a] Delete cluster")
        print("[s] Delete shard")
        print("[d] Delete replica")
        print()
        print("[p] Print cluster layout")
        print("[w] Write cluster layout")
        print("[u] pUsh cluster config")
        print()
        print("[q] Quit.")

        return input("What would you like to do? ")

    def interactive(self):
        choice = ''
        while choice != 'q':
            choice = self.get_interactive_choice()

            if choice == '1':
                self.add_cluster()
            elif choice == '2':
                self.add_shard()
            elif choice == '3':
                self.add_replica()
            elif choice == 'a':
                self.delete_cluster()
            elif choice == 's':
                self.delete_shard()
            elif choice == 'd':
                self.delete_replica()
            elif choice == 'p':
                self.print()
            elif choice == 'w':
                self.write()
            elif choice == 'u':
                self.push()
            elif choice == 'q':
                print("Thanks for playing. Bye.")
            else:
                print("I didn't understand that choice.")

    def main(self):
        if not self.open_config():
            print("Can't open config file %s" % (self.options['config.xml']))
            return

        self.ch_config_manager = CHConfigManager(self.config, self.options)
        if self.options['interactive']:
            self.interactive()
        else:
            print("Command mode not implemented yet")


if __name__ == '__main__':
    # print("RUN")
    manager = CHManager();
    manager.main()



    # from StringIO import StringIO
    # from lxml import etree
    # from lxml.etree import Element
    #
    # data = """<xml>
    #    <items>
    #       <pie>cherry</pie>
    #       <pie>apple</pie>
    #       <pie>chocolate</pie>
    #   </items>
    # </xml>"""

    # stream = StringIO(data)
    # context = etree.iterparse(stream, events=("start", ))
    #
    # for action, elem in context:
    #     if elem.tag == 'items':
    #         items = elem
    #         index = 1
    #     elif elem.tag == 'pie':
    #         item = Element('item', {'id': str(index)})
    #         items.replace(elem, item)
    #         item.append(elem)
    #         index += 1
    #
    # print etree.tostring(context.root)
    #
    # prints:
    #
    # <xml>
    #    <items>
    #       <item id="1"><pie>cherry</pie></item>
    #       <item id="2"><pie>apple</pie></item>
    #       <item id="3"><pie>chocolate</pie></item>
    #    </items>
    # </xml>
    #
    #
    # <example>
    #     <login>
    #         <id>1</id>
    #         <username>kites</username>
    #         <password>kites</password>
    #     </login>
    # </example>
    # example = etree.Element("example")
    # login = etree.SubElement(example, "login")
    # password = etree.SubElement(login,"password")
    # password.text = "newPassword"
