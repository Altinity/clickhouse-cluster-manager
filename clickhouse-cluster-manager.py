
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


class Manager:
    options = None

    def __init__(self):
        self.options = self.parse_options()

    def parse_options(self, config_folder='config'):
        return {
            'config-folder': config_folder,
            'config.xml': config_folder + '/config.xml',
            'user.xml': config_folder + '/user.xml'
        }

    def main(self):
        print("Running main")

        # tree = etree.parse('books.xml')
        # root = tree.getroot()
        #
        # print(etree.tostring(root, pretty_print=True).decode("utf-8"))
        # root.append(new_entry)
        # print(etree.tostring(root, pretty_print=True).decode("utf-8"))
        #
        # f = open('books-mod.xml', 'w')
        # f.write(etree.tostring(root, pretty_print=True).decode("utf-8"))
        # f.close()

        print(self.options)

        try:
            config_tree = etree.parse(self.options['config.xml'])
        except IOError:
            # file is not readable
            print("IOError")
        except etree.XMLSyntaxError:
            # file is readable, but has does not contain well-formed XML
            print("SyntaxError")


        # config_root = config_tree.getroot()
        # '<remote_servers>'
        remote_servers_element = config_tree.find('remote_servers')

        if remote_servers_element is None:
            # no <remote_servers> tag available
            return

        print("See remote_servers of type: " + str(type(remote_servers_element)))

        # iterate over <remote_servers> children elements
        # each tag inside it would be name of the cluster

        if len(remote_servers_element) > 0:
            print("See the following clusters:")
        else:
            print("No clusters defined")

        # walk over cluster's specifications
        for cluster_element in remote_servers_element:
            # skip comments
            if ConfigManager.is_element_comment(cluster_element):
                continue

            print("See cluster of type: " + str(type(cluster_element)))

            # normal element - cluster name <my_cool_cluster>
            print(cluster_element.tag)

            if len(cluster_element) > 0:
                print("See the following shards:")
            else:
                print("No shards defined")

            for shard_element in cluster_element:
                # skip comments
                if ConfigManager.is_element_comment(shard_element):
                    continue
                # skip everything what is not <shard> tag
                if shard_element.tag != 'shard':
                    continue

                print("See cluster of type: " + str(type(shard_element)))

                # normal element - <shard>
                print(shard_element.tag)

                if len(shard_element) > 0:
                    print("See the following replicas:")
                else:
                    print("No replicas defined")

                for replica_element in shard_element:
                    # skip comments
                    if ConfigManager.is_element_comment(replica_element):
                        continue

                    # skip everything what is not <replica> tag
                    if replica_element.tag != 'replica':
                        continue

                    print("See replica of type: " + str(type(replica_element)))

                    # normal element - <replica>
                    print(replica_element.tag)

                    host_element = replica_element.find('host')
                    port_element = replica_element.find('port')

                    print(host_element.tag)
                    print(host_element.text)
                    print(port_element.tag)
                    print(port_element.text)

                new_host_element = etree.Element('host')
                new_host_element.text = 'super-duper-host'
                new_port_element = etree.Element('port')
                new_port_element.text = '9001'

                new_replica_element = etree.Element('replica')
                new_replica_element.append(new_host_element)
                new_replica_element.append(new_port_element)

                shard_element.append(new_replica_element)

        f = open('test.xml', 'w')
        f.write(etree.tostring(config_tree, pretty_print=True).decode("utf-8"))
        f.close()


class ConfigManager:

    @staticmethod
    def is_element_comment(element):
        return isinstance(element, lxml.etree._Comment)


if __name__ == '__main__':
    print("RUN")
    #manager = Manager();
    #manager.main()

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
