
import lxml
from lxml import etree

import os
import paramiko

class SSHCopier:
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
            files_to_copy=[]
    ):
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.rsa_private_key_filename = rsa_private_key_filename
        self.dir_remote = dir_remote
        self.files_to_copy = files_to_copy

    def copy_files_list(self):
        """
        Tries first to connect using a private key from a private key file
        or provided by an SSH agent. If RSA authentication fails, then
        password login is attempted.
        """

        # get host key, if we know one
        hostkeytype = None
        hostkey = None
        files_copied = 0

        # build dictionary of known hosts
        try:
            host_keys = paramiko.util.load_host_keys(os.path.expanduser('~/.ssh/known_hosts'))
        except:
            # can't open known_hosts
            host_keys = {}

        if self.hostname in host_keys:
            # known host
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
            return 0

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
    config = None

    def __init__(self, config):
        self.config = config

    @staticmethod
    def is_element_comment(element):
        return isinstance(element, lxml.etree._Comment)

    def add_cluster(self, cluster_name):
        def on_cluster_root(remote_servers_element):
            new_cluster_element = etree.Element(cluster_name)
            remote_servers_element.append(new_cluster_element)

        return self.walk_config(on_cluster_root=on_cluster_root)

    def add_shard(self, cluster_name):
        def on_cluster(cluster_element, cluster_element_index):
            if cluster_element.tag != cluster_name:
                return
            new_shard_element = etree.Element('shard')
            cluster_element.append(new_shard_element)

        return self.walk_config(on_cluster=on_cluster)

    def add_replica(self, cluster_name, shard_index, host, port):
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
        def on_cluster(cluster_element, cluster_element_index):
            if cluster_element.tag != cluster_name:
                return
            cluster_element.getparent().remove(cluster_element)

        return self.walk_config(on_cluster=on_cluster)

    def delete_shard(self, cluster_name, shard_index):
        def on_shard(cluster_element, cluster_element_index, shard_element, shard_element_index):
            if cluster_element.tag != cluster_name:
                return

            if shard_element_index != shard_index:
                return

            cluster_element.remove(shard_element)

        return self.walk_config(on_shard=on_shard)

    def delete_replica(self, cluster_name, shard_index, host, port):
        def on_replica(cluster_element, cluster_element_index, shard_element, shard_element_index, replica_element, replica_element_index):
            if cluster_element.tag != cluster_name:
                return

            if shard_element_index != shard_index:
                return

            shard_element.remove(replica_element)

        return self.walk_config(on_replica=on_replica)

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
            on_cluster_root = None,
            on_cluster = None,
            on_shard = None,
            on_replica = None
    ):
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

    def demo(self):
        self.walk_config(
            on_cluster=self.on_cluster,
            on_shard=self.on_shard,
            on_replica=self.on_replica
        )


class CHManager:
    options = None
    config = None
    ch_config_manager = None

    def __init__(self):
        self.options = self.parse_options()

    def parse_options(self, config_folder='config'):
        return {
            'config-folder': config_folder,
            'config.xml': config_folder + '/config.xml',
            'user.xml': config_folder + '/user.xml'
        }

    def open_config(self):
        f = open(self.options['config.xml'], 'rb')
        self.config = f.read()
        f.close()

    def write_config(self):
        f = open('test.xml', 'wb')
        f.write(self.config)
        f.close()

    @staticmethod
    def parse_element(line):
        # /cluster/0/host:port

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
            shard_index = int(parts[2])
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
        print()
        print("[q] Quit.")

        return input("What would you like to do? ")

    def interactive(self):
        choice = ''
        while choice != 'q':

            choice = self.get_interactive_choice()

            if choice == '1':
                print("Add cluster")
                c = self.parse_element(input("Cluster name to add:"))
                print(c)
                self.config = self.ch_config_manager.add_cluster(c['cluster'])

            elif choice == '2':
                print("Add shard")
                c = self.parse_element(input("Cluster name to add shard:"))
                print(c)
                self.config = self.ch_config_manager.add_shard(c['cluster'])

            elif choice == '3':
                print("Add replica")
                c = self.parse_element(input("Cluster path for replica:"))
                print(c)
                self.config = self.ch_config_manager.add_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

            elif choice == 'a':
                print("Delete cluster")
                c = self.parse_element(input("Cluster name to delete:"))
                print(c)
                self.config = self.ch_config_manager.delete_cluster(c['cluster'])

            elif choice == 's':
                print("Delete shard")
                c = self.parse_element(input("Cluster path for shard:"))
                print(c)
                self.config = self.ch_config_manager.delete_shard(c['cluster'], c['shard_index'])

            elif choice == 'd':
                print("Delete replica")
                c = self.parse_element(input("Cluster path for replica:"))
                print(c)
                self.config = self.ch_config_manager.delete_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

            elif choice == 'p':
                print("Print cluster layout")
                print(self.config.decode())

            elif choice == 'w':
                print("Write cluster layout to disk")
                self.write_config()

            elif choice == 'q':
                print("Thanks for playing. Bye.")

            else:
                print("I didn't understand that choice.")

    def main(self):
        self.open_config()
        self.ch_config_manager = CHConfigManager(self.config)
        self.interactive()


if __name__ == '__main__':
    # print("RUN")
    manager = CHManager();
    manager.main()

        #    copier = SSHCopier(
#        hostname='192.168.74.157',
#        password='wax2bee692',
#        dir_remote='/home/user/',
#        files_to_copy=['/home/user/copytest.txt']
#    )
#    copier.copy_files_list()




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
