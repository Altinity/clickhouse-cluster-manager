#!/usr/bin/env python
# -*- coding: utf-8 -*-


import os
import tempfile
import lxml
from lxml import etree

from .sshcopier import SSHCopier


class CHConfigManager:
    """ClickHouse configuration manager

    :param config string configuration content
    """

    # string - XML configuration content
    ch_config = None

    # Config object
    config = None

    def __init__(self, ch_config, config):
        self.ch_config = ch_config
        self.config = config

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
                # this is not our cluster
                return
            # this is our cluster, add shard
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
                # this is not our cluster
                return

            if shard_element_index != shard_index:
                # this is not our shard
                return

            # this is our cluster + shard, add replica
            new_replica_element = etree.Element('replica')

            new_host_element = etree.Element('host')
            new_host_element.text = host
            new_port_element = etree.Element('port')
            new_port_element.text = port

            new_replica_element.append(new_host_element)
            new_replica_element.append(new_port_element)

            # append replica to the shard
            shard_element.append(new_replica_element)

        return self.walk_config(on_shard=on_shard)

    def delete_cluster(self, cluster_name):
        """
        Delete cluster from clusters specification

        :param cluster_name:
        :return:
        """
        def on_cluster(cluster_element, cluster_element_index):
            if cluster_element.tag != cluster_name:
                # this is not our cluster
                return
            # this is our cluster, remove current cluster from it's parent
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
                # this is not our cluster
                return

            if shard_element_index != shard_index:
                # this is not our shard
                return

            # this is our cluster and our shard
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
                # this is not our cluster
                return

            if shard_element_index != shard_index:
                # this is not our shard
                return

            # this is our cluster and our shard
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
        os.write(fd, self.ch_config)
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
                username=self.config.ssh_username(),
                password=self.config.ssh_password(),
                dir_remote='/etc/clickhouse-server/',
                files_to_copy=[tempfile_path],
                dry=self.config.dry()
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
            config_tree = etree.fromstring(self.ch_config, etree.XMLParser(remove_blank_text=True, encoding="utf-8"))
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

        # <remote_servers> found

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

            # shards have no names, so they need to be indexed in order to be accessed personally
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

                # replicas have no names, so they need to be indexed in order to be accessed personally
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

        # buld XML out of elements tree we have
        self.ch_config = etree.tostring(config_tree, pretty_print=True)
        return self.ch_config
