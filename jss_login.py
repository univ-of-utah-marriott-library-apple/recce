# -*- coding: utf-8 -*-
"""
This should not be blank.
"""

# Copyright (c) 2019 University of Utah, Marriott Library, #####################
# Client Platform Services. All Rights Reserved.
#
# Permission to use, copy, modify, and distribute this software and
# its documentation for any purpose and without fee is hereby granted,
# provided that the above copyright notice appears in all copies and
# that both that copyright notice and this permission notice appear
# in supporting documentation, and that the name of The University
# of Utah not be used in advertising or publicity pertaining to
# distribution of the software without specific, written prior
# permission. This software is supplied as is without expressed or
# implied warranties of any kind.
################################################################################

# jss_login.py #################################################################
#
# A Python module to verify user credentials and level of access.
#
#
#    1.1.0      2019.07.16      Initial version. tjm
#
#    1.1.1      2019.07.22      Adjusted server url handling. tjm
#
#
################################################################################

from __future__ import division
from __future__ import print_function

import base64
import getpass
import inspect
import json
import os
import pathlib
import platform
import sys

try:
    import urllib
except ImportError:
    from urllib.parse import quote

try:
    import pwd  # unix only?
except ImportError:
    pass

import configparser
import requests

__version__ = "1.1"


class Login():
    """
    Login object handles checking of JAMF user and group privileges, finding users highest level of access
    and reads or creates configuration file, as needed.
    """
    def __init__(self, logger, args):
        """
        This should not be blank.
        """

        self.logger = logger
        self.args = args
        self.jamf_username = "duplicate_search_results"
        self.jamf_password = "Joe"
        self.jamf_hostname = "Sally"
        self.slack_url = None
        self.config_path = ''
        self.config_file = None
        self.valid_hostname = ""
        self.validated_state = False
        self.write_prefs = False

        # read config file
        self.read_create_prefs()

        # self.display_config()

        working_server_name = self.config_file.get('login', 'hosts')

        if "https" not in working_server_name:
            if "http" in working_server_name:
                working_server_name.replace("http", "https")
            else:
                working_server_name = "https://" + working_server_name

        if "jamfcloud" and "8443" not in working_server_name:
            working_server_name = working_server_name +  ":8443"

        self.config_file.set('login', 'hosts', working_server_name)

        #
        # THIS IS REALLY IMPORTANT. This list contains the required rights for the fields we need to access
        # Could be moved to configuration file, if appropriate.
        self.read_privileges = ['Read Computers', 'Read LDAP Servers', 'Read Accounts', 'Read User']
        self.update_privileges = ['Update Computers', 'Update User']
        self.create_privileges = ['Create Computers', 'Create User']

        self.try_login()

        if self.validated_state and self.write_prefs:
            self.modify_prefs()

    def validated_creds(self):
        """
        Returns validated JAMF username, password, JAMF hostname and slack address.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        if self.validated_state:
            return self.config_file.get('login', 'username'), self.config_file.get('login', 'access'), self.config_file.get('login', 'hosts'), self.config_file.get('slack', 'slack_info_url')
        else:
            return None, None, None, None

    def display_config(self):
        """
        Display configuration file to the console. Largely for debugging purposes.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        print(self.config_file.sections())
        for item in self.config_file.sections():
            print(self.config_file.items(item))

    def try_login(self):
        """
        Attempts to verify the provided username and password for baseline access to the JAMF server.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        def call_jss(api_call):
            """
            consolidate API calls to single function
            pass in logger and api call.
            """
            self.logger.info("%s: activated" % inspect.stack()[0][3])

            try:
                url = self.config_file.get('login', 'hosts') + '/JSSResource/' + api_call

                self.logger.info("%s called with %s" % (inspect.stack()[0][3], api_call))

                response = requests.get(url, headers={'Accept': 'application/json'}, auth=(self.config_file.get('login', 'username'), self.config_file.get('login', 'access')))

                self.logger.info("Code returned: %s %s" % (response.status_code, api_call))

                if response.status_code != 200:
                    self.logger.error("login: Invalid response from Jamf (" + api_call + ")")
                    sys.exit()

                response_json = json.loads(response.text)

                return response_json

            #
            # handle various communication errors
            except requests.exceptions.HTTPError as this_error:
                self.logger.error("http error %s: %s\n" % (response.status_code, this_error))

                if response.status_code == 400:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Request error."))
                elif response.status_code == 401:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Authorization error."))
                elif response.status_code == 403:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Permissions error."))
                elif response.status_code == 404:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Resource not found."))
                elif response.status_code == 409:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Resource conflict. " + this_error))
                else:
                    self.logger.error("HTTP code {}: {}".format(response.status_code, "Generic error."))

            except requests.exceptions.ConnectionError as this_error:
                self.logger.error("%s: Error contacting JSS: %s" % (inspect.stack()[0][3], self.config_file.get('login', 'hosts')))

            except requests.exceptions.RequestException as this_error:
                self.logger.error("%s: Generic Error: %s" % (inspect.stack()[0][3], this_error))

            #
            # handle bad condition exits here...
            self.logger.error("%s: Exiting, Error calling %s" % (inspect.stack()[0][3], api_call))
            sys.exit()

        try:
            #
            # Polls JAMF server for list and specs of LDAP groups.
            # Further parses groups for correct access privileges.
            jss_accounts = call_jss('accounts')

            raw_ldap = call_jss('ldapservers')
            ldap_servers = raw_ldap['ldap_servers']
            self.logger.info("JSS LDAP servers: %r" % ldap_servers)

            #
            # store list of user and group privileges
            group_list = jss_accounts['accounts']['groups']

            #
            # find groups on jss that have required_privileges
            valid_full_groups = []

            for item in group_list:
                missing_ldap_read_privileges = []
                missing_ldap_update_privileges = []
                missing_ldap_create_privileges = []
                valid_ldap_read = False
                valid_ldap_update = False
                valid_ldap_create = False

                raw_privs = call_jss('accounts/groupid/' + str(item['id']))
                this_group_privs = raw_privs['group']['privileges']['jss_objects']

                for read_item in self.read_privileges:
                    if read_item not in this_group_privs:
                        missing_ldap_read_privileges.append(read_item)
                if not missing_ldap_read_privileges:
                    valid_ldap_read = True

                for create_item in self.create_privileges:
                    if create_item not in this_group_privs:
                        missing_ldap_create_privileges.append(create_item)
                if not missing_ldap_create_privileges:
                    valid_ldap_create = True

                for update_item in self.update_privileges:
                    if update_item not in this_group_privs:
                        missing_ldap_update_privileges.append(update_item)
                if not missing_ldap_create_privileges:
                    valid_ldap_update = True

                if valid_ldap_read and valid_ldap_update and valid_ldap_create:
                    self.logger.info("%s is read, create and update valid." % item['name'])
                    valid_full_groups.append([item['id'], item['name']])

                else:
                    self.logger.error("login: Group %r lacks appropriate privileges: %r" % (item['name'], missing_ldap_read_privileges + missing_ldap_create_privileges + missing_ldap_update_privileges))

            #
            # find servers with valid groups the user is a member of
            valid_full_servers = []
#             valid_read_servers = []

            for server in ldap_servers:
                for group in valid_full_groups:
                    raw_group_membership = call_jss('ldapservers/id/' + str(server['id']) + '/group/' + urllib.parse.quote(str(group[1])) + '/user/' + self.config_file.get('login', 'username'))

                    if raw_group_membership['ldap_users']:
                        self.logger.info("login: %s is a member of full group %s on server %s" % (self.config_file.get('login', 'username'), group[1], server['name']))
                        valid_full_servers.append(server['name'])
                        self.validated_state = True

            #
            # Check user's privileges
            jss_update = False
            jss_read = False
            jss_create = False
            missing_read_privileges = []
            missing_update_privileges = []
            missing_create_privileges = []
            try:
                raw_privileges = call_jss('accounts/username/' + self.config_file.get('login', 'username'))

                if raw_privileges:
                    user_privileges = raw_privileges['account']['privileges']['jss_objects']

                    for item in self.read_privileges:
                        if item not in user_privileges:
                            missing_read_privileges.append(item)

                    if not missing_read_privileges:
                        jss_read = True

                    for item in self.create_privileges:
                        if item not in user_privileges:
                            missing_create_privileges.append(item)

                    if not missing_create_privileges:
                        jss_create = True

                    for item in self.update_privileges:
                        if item not in user_privileges:
                            missing_update_privileges.append(item)

                    if not missing_update_privileges:
                        jss_update = True

                    if missing_read_privileges or missing_update_privileges or missing_create_privileges:
                        self.logger.warning("login: %s is missing privileges for full access: %r" % (self.config_file.get('login', 'username'), missing_read_privileges + missing_update_privileges + missing_create_privileges))

            except Exception as exception_message:
                self.logger.warning("%s: Error checking user account info. (%r)" % (inspect.stack()[0][3], exception_message))

            #
            # if all require privileges accounted for, proceed
            # else alert and prepare to fail.
            if jss_read and jss_update and jss_create:
                self.logger.info("login: valid full user login. (%r)" % self.config_file.get('login', 'username'))
                self.validated_state = True
                return
            else:
                self.logger.error("login: User %r lacks appropriate privileges: %r" % (self.config_file.get('login', 'username'), missing_read_privileges + missing_update_privileges + missing_create_privileges))

        except Exception as exception_message:
            self.logger.warning("%s: Error. (%r)" % (inspect.stack()[0][3], exception_message))

    def modify_prefs(self):
        """
        Write out credentials to configuration file.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        enc_data = self.config_file.get('login', 'access')
        enc_data = base64.b64encode(bytes(enc_data, 'utf-8'))
        self.config_file.set('login', 'access', str(enc_data, 'utf-8'))

        if not self.args.system_specific:
            self.config_path = pathlib.Path(os.path.dirname(os.path.realpath(sys.argv[0])), self.config_name)

        try:
            with open(self.config_path, "w") as config_write:
                self.config_file.write(config_write)
                self.logger.info("Wrote configuration file at %s." % self.config_path)

                dec_data = self.config_file.get('login', 'access')
                self.config_file.set('login', 'access', str(base64.b64decode(dec_data), 'utf-8'))

        except Exception as exception_message:
            self.logger.error("Error writing configuration file [%s]. %s" % (self.config_path, exception_message))

    def manual_login(self):
        """
        If no configuration file is found, ask the user for credentials and hostname of JAMF server.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        self.config_file.set('login', 'username', input("JSS username? "))
        self.config_file.set('login', 'access', getpass.getpass("JSS password? "))
        self.config_file.set('login', 'hosts', input("JSS hostname? "))
        self.config_file.set('slack', 'slack_info_url', input("Slack URL? "))
        self.write_prefs = True

    def read_create_prefs(self):
        """
        Attempt to locate configuration file.
        Will look in the same directory as the script, or in a platform specific, standard location.
        If not found, create a blank data structure for potential file creation.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        executable_name = os.path.basename(sys.argv[0])

        # this is still not working correctly, it appears.
        if executable_name.count('.') > 1:
            filename = executable_name.split('.')[:-1]
            filename = '.'.join(filename)
        else:
            filename = executable_name.split('.')[0]

        try:
            if '_' in filename:
                split_filename = filename.split('_')
                try:
                    # source of error: invalid literal for int() with base 10: 'l'
                    int(split_filename[-1][0])
                    del split_filename[-1]
                except Exception as exception_message:
                    self.logger.error(exception_message)
                self.config_name = 'edu.scl.utah.' + '_'.join(split_filename) + '.ini'
            else:
                self.config_name = 'edu.scl.utah.' + filename + '.ini'

        except Exception as exception_message:
            self.logger.error("Error creating config_name [%s]. %s" % (executable_name, exception_message))
            # bad
            return '', ''

        # okay. check local path exists, else look for platform specific location.
        local_path = pathlib.Path(os.path.dirname(os.path.realpath(sys.argv[0])), self.config_name)

        if os.path.exists(local_path):
            self.logger.info("%s: using local config file." % inspect.stack()[0][3])
            self.config_path = local_path
        else:
            if platform.system() == 'Darwin':
                if os.path.exists(pwd.getpwuid(os.getuid())[5] + os.path.join('/', 'Library', 'Preferences', self.config_name)):
                    self.config_path = pwd.getpwuid(os.getuid())[5] + os.path.join('/', 'Library', 'Preferences', self.config_name)
                elif os.path.exists(os.path.join('/', 'Library', 'Preferences', self.config_name)):
                    self.config_path = os.path.join('/', 'Library', 'Preferences', self.config_name)
                else:
                    self.config_path = pwd.getpwuid(os.getuid())[5] + os.path.join('/', 'Library', 'Preferences', self.config_name)

            elif platform.system() == 'Windows':
                # add enclosing folder!
                self.config_path = pathlib.Path(os.environ['SYSTEMDRIVE'], os.sep, 'ProgramData', 'edu.scl.utah.recce', self.config_name)

            elif platform.system() == 'Linux':
                # find the correct location for the config file.
                pass

        if not os.path.exists(self.config_path):
            if self.args.quit_config:
                self.logger.critical("Configuration file not found, exiting.")
                quit()
            else:
                self.logger.warning("Configuration file not found, creating structure in memory.")

                try:
                    self.config_path.parent.mkdir()
                except FileExistsError:
                    self.logger.critical("Unable to create paths to configuration file, exiting.")
                    quit()

                self.config_file = configparser.ConfigParser(allow_no_value=True)
                self.config_file.add_section('login')
                self.config_file.set('login', 'hosts', '')
                self.config_file.set('login', 'username', '')
                self.config_file.set('login', 'access', '')
                self.config_file.add_section('slack')
                self.config_file.set('slack', 'slack_info_url', '')

                self.manual_login()
        else:
            #
            # What?
            # need to handle which config file is priority and process
            self.config_file = configparser.ConfigParser(allow_no_value=True)
            try:
                if not self.args.manual_login:
                    self.config_file.read(self.config_path)

                    dec_data = self.config_file.get('login', 'access')
                    self.config_file.set('login', 'access', str(base64.b64decode(dec_data), 'utf-8'))

                else:
                    self.config_file.add_section('login')
                    self.config_file.set('login', 'hosts', '')
                    self.config_file.set('login', 'username', '')
                    self.config_file.set('login', 'access', '')
                    self.config_file.add_section('slack')
                    self.config_file.set('slack', 'slack_info_url', '')

                    self.manual_login()
            except Exception as exception_message:
                self.logger.error("Error reading pre-exiting configuration file [%s]. %s" % (self.config_path, exception_message))

                self.config_file = configparser.ConfigParser(allow_no_value=True)
                self.config_file.add_section('login')
                self.config_file.set('login', 'hosts', '')
                self.config_file.set('login', 'username', '')
                self.config_file.set('login', 'access', '')
                self.config_file.add_section('slack')
                self.config_file.set('slack', 'slack_info_url', '')

                self.manual_login()

        self.logger.info("Configuration path: %s" % self.config_path)
