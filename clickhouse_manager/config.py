#!/usr/bin/env python
# -*- coding: utf-8 -*-


class Config(object):

    config = None

    def __init__(self, config):
        self.config = config

    def __str__(self):
        return str(self.config)

    def __getitem__(self, item):
        return self.config[item]

    def interactive(self):
        return self.config['app']['interactive']

    def dry(self):
        return self.config['app']['dry']

    def log_file(self):
        return self.config['app']['log-file']

    def log_level(self):
        return self.config['app']['log-level']

    def pid_file(self):
        return self.config['app']['pid_file']

    def ch_config_folder(self):
        return self.config['manager']['config-folder']

    def ch_config_file(self):
        return self.config['manager']['config.xml']

    def ch_config_user_file(self):
        return self.config['manager']['user.xml']

    def ssh_username(self):
        return self.config['ssh']['username']

    def ssh_password(self):
        return self.config['ssh']['password']

    def ssh_port(self):
        return self.config['ssh']['port']
