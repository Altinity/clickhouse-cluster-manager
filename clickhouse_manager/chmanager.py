#!/usr/bin/env python
# -*- coding: utf-8 -*-


import logging
import pprint
import re

from .cliopts import CLIOpts
from .chconfigmanager import CHConfigManager


class CHManager:
    """
    High-level class for managing CH cluster configuration
    """
    config = None
    ch_config = None
    ch_config_manager = None

    def __init__(self):
        self.config = CLIOpts.config()

        logging.basicConfig(
            filename=self.config.log_file(),
            level=self.config.log_level(),
            format='%(asctime)s/%(created)f:%(levelname)s:%(message)s'
        )
        logging.info('Starting')
        logging.debug(pprint.pformat(self.config.config))

    def open_config(self):
        try:
            f = open(self.config.ch_config_file(), 'rb')
            self.ch_config = f.read()
            f.close()
            return True
        except:
            return False

    def write_config(self):
        f = open('test.xml', 'wb')
        f.write(self.ch_config)
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

        # ensure starting '/'
        if not line.startswith('/'):
            line = '/' + line

        try:
            parts = line.split('/')
        except:
            parts = []

        # parts[0] would be empty, ignore it
        # fetch cluster - parts[1]
        try:
            cluster = parts[1]
        except IndexError:
            # parts[1] - cluster - unavailable
            cluster = None

        # fetch shard - parts[2]
        try:
            # would like to consume both ways
            # .../0/...
            # .../shard0/...
            # so strip all non-numbers in the list
            shard_index = int(re.sub('[^0-9]', '', parts[2]))
        except IndexError:
            # parts[2] - chard - unavailable or malformed
            shard_index = None

        # fetch host:port - parts[3]
        try:
            host_port = parts[3]
            host_port = host_port.split(':')
            host = host_port[0]
            port = host_port[1]
        except IndexError:
            # parts[3] - host:port - unavailable or malformed
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
        print('Cluster path example /cluster1/shard0/host:port')
        pass

    def add_cluster(self):
        """High-level add cluster"""
        print("Add cluster")
        c = self.cluster_path_parse(input("Cluster name to add:"))
        print(c)
        self.ch_config = self.ch_config_manager.add_cluster(c['cluster'])

    def add_shard(self):
        """High-level add shard"""
        print("Add shard")
        c = self.cluster_path_parse(input("Cluster name to add shard:"))
        print(c)
        self.ch_config = self.ch_config_manager.add_shard(c['cluster'])

    def add_replica(self):
        """High-level add replica"""
        print("Add replica")
        self.cluster_path_print()
        c = self.cluster_path_parse(input("Cluster path for replica:"))
        print(c)
        self.ch_config = self.ch_config_manager.add_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

    def delete_cluster(self):
        """High-level delete cluster"""
        print("Delete cluster")
        c = self.cluster_path_parse(input("Cluster name to delete:"))
        print(c)
        self.ch_config = self.ch_config_manager.delete_cluster(c['cluster'])

    def delete_shard(self):
        """High-level delete shard"""
        print("Delete shard")
        c = self.cluster_path_parse(input("Cluster path for shard:"))
        print(c)
        self.ch_config = self.ch_config_manager.delete_shard(c['cluster'], c['shard_index'])

    def delete_replica(self):
        """High-level delete replica"""
        print("Delete replica")
        self.cluster_path_print()
        c = self.cluster_path_parse(input("Cluster path for replica:"))
        print(c)
        self.ch_config = self.ch_config_manager.delete_replica(c['cluster'], c['shard_index'], c['host'], c['port'])

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
                print("Can't understand that choice.")

    def main(self):
        """Main function. Global entry point."""
        if not self.open_config():
            print("Can't open config file {}".format(self.config.ch_config_file()))
            return

        self.ch_config_manager = CHConfigManager(self.ch_config, self.config)
        if self.config.interactive():
            self.interactive()
        else:
            print("Command mode not implemented yet")
