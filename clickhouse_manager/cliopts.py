#!/usr/bin/env python
# -*- coding: utf-8 -*-


import argparse
import logging
import os

from .config import Config


class CLIOpts(object):

    @staticmethod
    def join(lists_to_join):
        """Join several lists into one

        :param lists_to_join: is a list of lists
        [['a=b', 'c=d'], ['e=f', 'z=x'], ]

        :return: None or dictionary
        {'a': 'b', 'c': 'd', 'e': 'f', 'z': 'x'}

        """

        if not isinstance(lists_to_join, list):
            return None

        res = {}
        for lst in lists_to_join:
            # lst = ['a=b', 'c=d']
            for column_value_pair in lst:
                # column_value_value = 'a=b'
                column, value = column_value_pair.split('=', 2)
                res[column] = value

        # res = dict {
        #   'col1': 'value1',
        #   'col2': 'value2',
        # }

        # return with sanity check
        if len(res) > 0:
            return res
        else:
            return None

    @staticmethod
    def log_level_from_string(log_level_string):
        """Convert string representation of a log level into logging.XXX constant"""

        level = log_level_string.upper()

        if level == 'CRITICAL':
            return logging.CRITICAL
        if level == 'ERROR':
            return logging.ERROR
        if level == 'WARNING':
            return logging.WARNING
        if level == 'INFO':
            return logging.INFO
        if level == 'DEBUG':
            return logging.DEBUG
        if level == 'NOTSET':
            return logging.NOTSET

        return logging.NOTSET

    @staticmethod
    def config():
        """Parse application's CLI options into options dictionary
        :return: instance of Config
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
            '--log-file',
            type=str,
            default=None,
            help='Path to log file. Default - not specified'
        )
        argparser.add_argument(
            '--log-level',
            type=str,
            default="NOTSET",
            help='Log Level. Default - NOTSET'
        )
        argparser.add_argument(
            '--pid-file',
            type=str,
            default='/tmp/reader.pid',
            help='Pid file to be used by the app'
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
        return Config({

            'app': {
                'interactive': args.interactive,
                'config-file': args.config_file,
                'dry': args.dry,
                'log-file': args.log_file,
                'log-level': CLIOpts.log_level_from_string(args.log_level),
                'pid_file': args.pid_file,
            },

            'ssh': {
                'username': args.ssh_user,
                'password': args.ssh_password,
                'port': args.ssh_port,
            },

            'manager': {
                'config-folder': os.path.abspath(args.config_folder),
                'config.xml': os.path.abspath(args.config_folder + '/' + getattr(args, 'config.xml')),
                'user.xml': os.path.abspath(args.config_folder + '/' + getattr(args, 'user.xml'))
            },
        })
