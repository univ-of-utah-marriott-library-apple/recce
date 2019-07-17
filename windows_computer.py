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

# windows_computer.py ##########################################################
#
# Module to interogate and report Windows hardware and software information to
# Jamf database.
#
#    1.0.2      2019.07.16      Initial version. tjm
#
#
################################################################################

from __future__ import division
from __future__ import print_function

import datetime
import hashlib
import inspect
import json
import math
import platform
import random
import re
import subprocess

import requests

__version__ = "1.0.2"


class Computer():
    """
    This should not be blank.
    """

    def __init__(self, logger, jss_user, jss_pwrd, jss_host, slack_url, version):
        """
        Initialize object
        """

        self.logger = logger

        current_platform = platform.system()
        if current_platform == 'Windows':
            local_uuid_raw = subprocess.check_output("wmic CsProduct Get UUID")
            self.local_uuid = local_uuid_raw.split()[1]
        else:
            self.logger.error("%s: Non-Windows based computer. Exiting." % inspect.stack()[0][3])
            quit()

        self.jss_user = jss_user
        self.jss_pwrd = jss_pwrd
        self.jss_host = jss_host
        self.slack_url = slack_url
        self.version = version

        self.computer_xml_string = ""
        self.device_xml_string = ""
        self.output_xml_string = ""
        self.duplicate_detected = False
        self.jss_computer_id = ""

        self.xml_string = ""
        self.ram_slots = 0
        self.ipv6_address = None

        self.computer_dict = {
            "computer": {
                "general": {
                    "id": 0,
                    "name": None,
                    "mac_address": None,
                    "alt_mac_address": None,
                    "ip_address": None,
                    "last_reported_ip": None,
                    "serial_number": None,
                    "udid": None,
                    "jamf_version": None,
                    "platform": None,
                    "barcode_1": None,
                    "asset_tag": None,
                    "remote_management": {
                        "managed": None
                    },
                    "mdm_capable": None,
                    "report_date": None,
                    "report_date_epoch": None,
                    "report_date_utc": None,
                    "last_contact_time": None,
                    "last_contact_time_epoch": None,
                    "last_contact_time_utc": None,
                    "initial_entry_date": None,
                    "initial_entry_date_epoch": None,
                    "initial_entry_date_utc": None,
                    "last_cloud_backup_date_epoch": None,
                    "last_enrolled_date_epoch": None,
                    "last_enrolled_date_utc": None,
                    "site": {
                        "id": None,
                        "name": None
                    },
                    "itunes_store_account_is_active": None
                },
                "hardware": {
                    "make": None,
                    "model": None,
                    "model_identifier": None,
                    "os_name": None,
                    "os_version": None,
                    "os_build": None,
                    "master_password_set": None,
                    "active_directory_status": None,
                    "processor_type": None,
                    "processor_architecture": None,
                    "processor_speed": None,
                    "processor_speed_mhz": None,
                    "number_processors": None,
                    "number_cores": None,
                    "total_ram": None,
                    "total_ram_mb": None,
                    "boot_rom": None,
                    "bus_speed": None,
                    "bus_speed_mhz": None,
                    "battery_capacity": None,
                    "cache_size": None,
                    "cache_size_kb": None,
                    "available_ram_slots": None,
                    "nic_speed": None,
                    "smc_version": None,
                    "ble_capable": None,
                    "sip_status": None,
                    "gatekeeper_status": None,
                    "xprotect_version": None,
                    "institutional_recovery_key": None,
                    "optical_drive": None,
                    "storage": {
                        "placeholder": "duplicate_search_results"
                    }
                }
            }
        }

        self.device_string = ""

        self.device_list = []

        self.logger.info("Start fetching hardware info.")
        self.build_hardware_inventory()

        self.logger.info("Start clean_dict.")
        self.clean_dict()

        self.logger.info("Start xml_from_dict.")
        self.xml_from_dict(self.computer_dict)
        self.computer_xml_string = self.xml_string

        self.logger.info("Start fetching disk info.")
        self.build_disk_inventory()

        self.logger.info("Start formatting disk info.")
        test_device_xml = ""
        self.xml_string = ""

        test_device_xml += "<storage>"

        for item in self.device_list:

            if isinstance(item, dict):
                test_device_xml += "<device>"
                self.xml_string = ""
                self.xml_from_dict(item)
                test_device_xml += self.xml_string

            if isinstance(item, list):
                for sub_item in item:
                    test_device_xml += "<partition>"
                    self.xml_string = ""
                    self.xml_from_dict(sub_item)
                    test_device_xml += self.xml_string

                    test_device_xml += "</partition>"

                test_device_xml += "</device>"

        test_device_xml += "</storage>"

        self.device_xml_string = test_device_xml

        storage_stub = "<storage><placeholder>duplicate_search_results</placeholder></storage>"
        self.output_xml_string = self.computer_xml_string.replace(storage_stub, self.device_xml_string)

    def ipconfig_to_dict(self, raw_command):
        """
        Converts the return of a ipconfig command into a dictionary and returns results.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        dict_command = {}

        try:
            raw_command = raw_command.decode("utf-8")
        except Exception as this_exception:
            self.logger.error("Error decoding command, will ignore errors. %s" % this_exception)
            raw_command = raw_command.decode("utf-8", "ignore")

        split_command = raw_command.split("\r\n")
        split_command = [x for x in split_command if x]

        for item in split_command:
            split_item = item.split(" : ")
            # print("%r" % split_item)

            if len(split_item) == 1:
                current_superkey = split_item[0]
                if current_superkey.endswith(":"):
                    current_superkey = current_superkey.replace(':', '')

                dict_command[current_superkey] = {}

            try:
                split_key = split_item[0].rstrip()
                split_value = split_item[1].rstrip()

                if ' .' in split_key:
                    temp_key = split_key.replace('.', '')
                    temp_key = temp_key.rstrip()
                    temp_key = temp_key.lstrip()
                    split_key = temp_key

                if '","' in split_value:
                    temp_value = split_value.replace('"', '')
                    temp_value = temp_value.rsplit()
                    split_value = temp_value

                try:
                    if dict_command[current_superkey][split_key] is not None:
                        if isinstance(dict_command[current_superkey][split_key], list):
                            dict_command[current_superkey][split_key].append(split_value)
                        else:
                            temp_value = dict_command[current_superkey][split_key]
                            dict_command[current_superkey][split_key] = [temp_value]
                            dict_command[current_superkey][split_key].append(split_value)
                except KeyError:
                    dict_command[current_superkey][split_key] = split_value

            except:
                pass

        return dict_command

    def command_to_dict(self, raw_command):
        """
        Converts the return of a wmic command into a dictionary and returns results.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        # what if the command returns multiple iterations?!?
        # if dict_command[item]:
        #   dict_command[item].append[value]
        # for example memorychip
        dict_command = {}

        try:
            raw_command = raw_command.decode("utf-8")
        except Exception as this_exception:
            self.logger.error("Error decoding command, will ignore errors. %s" % this_exception)
            raw_command = raw_command.decode("utf-8", "ignore")

        split_command = raw_command.split("\r\r\n")
        split_command = [x for x in split_command if x]

        for item in split_command:
            split_item = item.split("=")
            split_key = split_item[0].rstrip()
            split_value = split_item[1].rstrip()

            if '","' in split_value:
                temp_value = split_value.replace('"', '')
                temp_value = temp_value.replace('}', '')
                temp_value = temp_value.replace('{', '')
                split_value = temp_value.split(",")

            try:
                if dict_command[split_key] is not None:
                    if isinstance(dict_command[split_key], list):
                        dict_command[split_key].append(split_value)
                    else:
                        temp_value = dict_command[split_key]
                        dict_command[split_key] = [temp_value]
                        dict_command[split_key].append(split_value)
            except KeyError:
                # should this be assigning to a single item list?!?
                # how would that effect hardware_inventory?
                dict_command[split_key] = split_value

        return dict_command

    def build_hardware_inventory(self):
        """
        Provides the roadmap to gather the required hardware data, using methods to format the data returned by external commands.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        #
        # FIX THIS!
        #
        self.logger.info("fetching hostname.")
        try:
            self.computer_dict['computer']['general']['name'] = str(subprocess.check_output(["hostname"]).strip(), 'utf-8')
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling hostname.")
        except:
            self.logger.critical("Subprocess generic error calling hostname.")

        self.computer_dict['computer']['general']['platform'] = "Windows"

        # print("%r" % str(subprocess.check_output(["wmic", "CsProduct", "get", "UUID", "/format:value"]).strip(), 'utf-8').split("=")[1])

        # mac_address = str(uuid.getnode())
        # hostname = mac_address + '.scl.utah.edu'
        # this_uuid = uuid.uuid5(uuid.NAMESPACE_DNS, hostname)
        # temp_udid = str(this_uuid.urn)
        # self.computer_dict['computer']['general']['udid'] = temp_udid.split(":")[-1].upper()
        self.logger.info("fetching udid.")
        try:
            self.computer_dict['computer']['general']['udid'] = str(subprocess.check_output(["wmic", "CsProduct", "get", "UUID", "/format:value"]).strip(), 'utf-8').split("=")[1]
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic CsProduct get UUID /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic CsProduct get UUID /format:value'.")

        # bits to edit uuid
        # print(self.computer_dict['computer']['general']['udid'])
        # self.computer_dict['computer']['general']['udid'] = input("Test UUID? ")
        # print(self.computer_dict['computer']['general']['udid'])

        self.logger.info("fetching memorychip.")
        try:
            wmic_memchip_raw = subprocess.check_output(["wmic", "memorychip", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic memorychip get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic memorychip get * /format:value'.")
        wmic_memchip_dict = self.command_to_dict(wmic_memchip_raw)

        self.logger.info("fetching memphysical.")
        try:
            wmic_memphys_raw = subprocess.check_output(["wmic", "memphysical", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic memphysical get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic memphysical get * /format:value'.")
        wmic_memphys_dict = self.command_to_dict(wmic_memphys_raw)

        self.ram_slots = int(wmic_memphys_dict['MemoryDevices'])
        self.computer_dict['computer']['hardware']['available_ram_slots'] = self.ram_slots - len(wmic_memchip_dict['Capacity'])

        self.logger.info("fetching os.")
        try:
            wmic_os_raw = subprocess.check_output(["wmic", "os", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic os get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic os get * /format:value'.")
        wmic_os_dict = self.command_to_dict(wmic_os_raw)

        self.computer_dict['computer']['hardware']['os_version'] = wmic_os_dict['Version']
        self.computer_dict['computer']['hardware']['os_build'] = wmic_os_dict['BuildNumber']
        self.computer_dict['computer']['hardware']['os_name'] = wmic_os_dict['Caption']

        self.logger.info("fetching computersystem.")
        try:
            wmic_cs_raw = subprocess.check_output(["wmic", "computersystem", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic computersystem get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic computersystem get * /format:value'.")
        wmic_cs_dict = self.command_to_dict(wmic_cs_raw)

        self.computer_dict['computer']['hardware']['number_processors'] = wmic_cs_dict['NumberOfProcessors']
        self.computer_dict['computer']['hardware']['make'] = wmic_cs_dict['Manufacturer']
        self.computer_dict['computer']['hardware']['model'] = wmic_cs_dict['Model']
        self.computer_dict['computer']['hardware']['model_identifier'] = wmic_cs_dict['Model']

        self.computer_dict['computer']['hardware']['total_ram'] = sum(map(int, wmic_memchip_dict['Capacity']))
        self.computer_dict['computer']['hardware']['total_ram_mb'] = int(self.computer_dict['computer']['hardware']['total_ram'] / (1024 * 1024))

        self.logger.info("fetching nic.")
        try:
            wmic_nic_raw = subprocess.check_output(["wmic", "nic", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic nic get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic nic get * /format:value'.")
        wmic_nic_dict = self.command_to_dict(wmic_nic_raw)

        self.logger.info("nic_dict: %r" % wmic_nic_dict)

        self.logger.info("fetching nicconfig.")
        try:
            wmic_nicc_raw = subprocess.check_output(["wmic", "nicconfig", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic nicconfig get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic nicconfig get * /format:value'.")
        wmic_nicc_dict = self.command_to_dict(wmic_nicc_raw)

        self.logger.info("nicconfig_dict: %r" % wmic_nicc_dict)

        self.logger.info("fetching ipconfig.")
        try:
            ipconfig_raw = subprocess.check_output(["ipconfig", "/all"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'ipconfig /all'.")
        except:
            self.logger.critical("Generic error calling 'ipconfig /all'.")
        ipconfig_dict = self.ipconfig_to_dict(ipconfig_raw)

        self.logger.info("ipconfig_dict: %r" % ipconfig_dict)

        ethernet_mac = None
        ethernet_nic_speed = None
        ethernet_ip_address = None
        wireless_mac = None
        wireless_nic_speed = None
        wireless_ip_address = None

        for key, value in ipconfig_dict.items():
            # print("key: %s" % key)
            # for subkey, subvalue in value.items():
            #     print("\tk: %s v: %s" % (subkey, subvalue))

            if ethernet_mac:
                self.logger.info("Primary selected. Additional ethernet interface: {}".format(key))
                continue

            if wireless_mac:
                self.logger.info("Secondary selected. Additional wireless interface: {}".format(key))
                continue

            if "ethernet adapter" in key.lower() and "bluetooth" not in key.lower():
                try:
                    if value["Media State"]:
                        pass

                except KeyError:
                    if value['Default Gateway']:
                        ethernet_mac = value['Physical Address'].replace("-", ":")
                        ethernet_ip_address = value['IPv4 Address'].split('(Preferred)')[0]

                        self.computer_dict['computer']['general']['mac_address'] = ethernet_mac
                        self.computer_dict['computer']['general']['ip_address'] = ethernet_ip_address

                        for count, item in enumerate(wmic_nic_dict['MACAddress']):
                            if ethernet_mac == wmic_nic_dict['MACAddress'][count]:
                                if wmic_nic_dict['Speed'][count]:
                                    ethernet_nic_speed = wmic_nic_dict['Speed'][count]
                                    temp_speed = math.sqrt(int(ethernet_nic_speed) / 1000)
                                    if int(temp_speed) == 10000:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/10000"
                                    elif int(temp_speed) == 5000:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/5000"
                                    elif int(temp_speed) == 2500:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/2500"
                                    elif int(temp_speed) == 1000:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000"
                                    elif int(temp_speed) == 100:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10/100"
                                    elif int(temp_speed) == 10:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = "10"
                                    else:
                                        self.computer_dict['computer']['hardware']['nic_speed'] = wmic_nic_dict['Speed'][count]

                                # print(self.computer_dict['computer']['hardware']['nic_speed'])

            elif "wireless lan adapter" in key.lower() and "bluetooth" not in key.lower():
                try:
                    if value["Media State"]:
                        pass

                except KeyError:
                    wireless_mac = value['Physical Address'].replace("-", ":")
                    wireless_ip_address = value['IPv4 Address'].split('(Preferred)')[0]
                    self.computer_dict['computer']['general']['alt_mac_address'] = wireless_mac

            if not ethernet_mac:
                self.computer_dict['computer']['general']['mac_address'] = wireless_mac
                self.computer_dict['computer']['general']['alt_mac_address'] = None
                self.computer_dict['computer']['general']['ip_address'] = wireless_ip_address

        # print(ethernet_mac, ethernet_ip_address, ethernet_nic_speed)

        # https://weblogs.sqlteam.com/mladenp/2010/11/04/find-only-physical-network-adapters-with-wmi-win32_networkadapter-class/
        # primary_mac = None
        # primary_nic_speed = None
        # primary_ip_address = None
        # alt_mac = None
        # primary_nic_index = None
        # secondary_nic_index = None

        # for count, _ in enumerate(wmic_nic_dict['PNPDeviceID']):
        #     # if "ROOT\\" not in wmic_nic_dict['PNPDeviceID'][count]:
        #     if "PCI\\" in wmic_nic_dict['PNPDeviceID'][count]:
        #         if "ethernet" in wmic_nic_dict['ProductName'][count].lower():
        #             primary_nic_index = int(wmic_nic_dict['Index'][count])
        #         else:
        #             secondary_nic_index = int(wmic_nic_dict['Index'][count])

        # # need to rework...
        # # switch variables to ethernic and wifinic?
        # # just use ifconfig?

        # if primary_nic_index:
        #     primary_mac = wmic_nic_dict['MACAddress'][primary_nic_index]
        #     primary_nic_speed = wmic_nic_dict['Speed'][primary_nic_index]
        #     primary_nic_index = wmic_nic_dict['Index'][primary_nic_index]
        #     if secondary_nic_index:
        #         alt_mac = wmic_nic_dict['MACAddress'][secondary_nic_index]

        # if secondary_nic_index:
        #     if not primary_nic_index:
        #         primary_mac = wmic_nic_dict['MACAddress'][secondary_nic_index]
        #         primary_nic_speed = wmic_nic_dict['Speed'][secondary_nic_index]
        #         primary_nic_index = wmic_nic_dict['Index'][secondary_nic_index]

        # if alt_mac:
        #     self.computer_dict['computer']['general']['alt_mac_address'] = alt_mac

        # if primary_mac:
        #     self.computer_dict['computer']['general']['mac_address'] = primary_mac

        #     temp_speed = math.sqrt(int(primary_nic_speed)/1000)
        #     if int(temp_speed) == 10000:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/10000"
        #     elif int(temp_speed) == 5000:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/5000"
        #     elif int(temp_speed) == 2500:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/2500"
        #     elif int(temp_speed) == 1000:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000"
        #     elif int(temp_speed) == 100:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10/100"
        #     elif int(temp_speed) == 10:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = "10"
        #     else:
        #         self.computer_dict['computer']['hardware']['nic_speed'] = primary_nic_speed

        #     for count, item in enumerate(wmic_nicc_dict['MACAddress']):
        #         if item == self.computer_dict['computer']['general']['mac_address']:
        #             self.computer_dict['computer']['general']['ip_address'] = wmic_nicc_dict['IPAddress'][count][0]
        #             self.ipv6_address = wmic_nicc_dict['IPAddress'][count][1]

                # if item == "TRUE":
                #     temp_split = wmic_nicc_dict['IPAddress'][count]
                #     self.computer_dict['computer']['general']['mac_address'] = wmic_nicc_dict['MACAddress'][count]
                #     self.computer_dict['computer']['general']['ip_address'] = temp_split[0]
                #     self.ipv6_address = temp_split[1]

        # # what if there's more than one?!?
        # for count, item in enumerate(wmic_nicc_dict['IPEnabled']):
        #     if item == "TRUE":
        #         temp_split = wmic_nicc_dict['IPAddress'][count]
        #         self.computer_dict['computer']['general']['mac_address'] = wmic_nicc_dict['MACAddress'][count]
        #         self.computer_dict['computer']['general']['ip_address'] = temp_split[0]
        #         self.ipv6_address = temp_split[1]

        # # what if it's only the wireless interface?
        # for count, item in enumerate(wmic_nic_dict['MACAddress']):
        #     if item == self.computer_dict['computer']['general']['mac_address']:
        #         temp_speed = math.sqrt(int(wmic_nic_dict['Speed'][count])/1000)
        #         if int(temp_speed) == 10000:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/10000"
        #         elif int(temp_speed) == 5000:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/5000"
        #         elif int(temp_speed) == 2500:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000/2500"
        #         elif int(temp_speed) == 1000:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10/100/1000"
        #         elif int(temp_speed) == 100:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10/100"
        #         elif int(temp_speed) == 10:
        #             self.computer_dict['computer']['hardware']['nic_speed'] = "10"

        self.logger.info("fetching cpu.")
        try:
            wmic_cpu_raw = subprocess.check_output(["wmic", "cpu", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic cpu get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic cpu get * /format:value'.")
        wmic_cpu_dict = self.command_to_dict(wmic_cpu_raw)

        self.computer_dict['computer']['hardware']['processor_type'] = wmic_cpu_dict['Name']
        self.computer_dict['computer']['hardware']['processor_architecture'] = wmic_cpu_dict['Description']
        self.computer_dict['computer']['hardware']['number_cores'] = wmic_cpu_dict['NumberOfCores'] * int(self.computer_dict['computer']['hardware']['number_processors'])

        raw_cpu_speed = wmic_cpu_dict['MaxClockSpeed']
        raw_cpu_speed = int(raw_cpu_speed) / 1000
        raw_cpu_speed = "{:1.2f}".format(raw_cpu_speed)
        raw_cpu_speed = raw_cpu_speed + " GHz"

        self.computer_dict['computer']['hardware']['processor_speed'] = raw_cpu_speed

        self.logger.info("fetching bios.")
        try:
            wmic_bios_raw = subprocess.check_output(["wmic", "bios", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic bios get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic bios get * /format:value'.")
        wmic_bios_dict = self.command_to_dict(wmic_bios_raw)
        # should this be from csproduct?
        self.computer_dict['computer']['general']['serial_number'] = wmic_bios_dict['SerialNumber']
        self.computer_dict['computer']['hardware']['boot_rom'] = wmic_bios_dict['Version']

        self.logger.info("fetching cdrom.")
        try:
            wmic_cdrom_raw = subprocess.check_output(["wmic", "cdrom", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic cdrom get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic cdrom get * /format:value'.")
        wmic_cdrom_dict = self.command_to_dict(wmic_cdrom_raw)

        try:
            self.computer_dict['computer']['hardware']['optical_drive'] = wmic_cdrom_dict['Caption']
            self.computer_dict['computer']['hardware']['optical_drive'] = self.mitigate_issues(self.computer_dict['computer']['hardware']['optical_drive'], 40)
        except:
            pass

        self.identify_duplicates()

    def build_disk_inventory(self):
        """
        Manages the calls to different commands, formating of results, parsing results and deriving final results.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

#         disk_list = []

        self.logger.info("%s: activated" % inspect.stack()[0][3])

        # un-needed?!?
        try:
            wmic_volume_raw = subprocess.check_output(["wmic", "volume", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic volume get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic volume get * /format:value'.")
        wmic_volume_dict = self.command_to_dict(wmic_volume_raw)

        try:
            wmic_diskdrive_raw = subprocess.check_output(["wmic", "diskdrive", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic diskdrive get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic diskdrive get * /format:value'.")
        wmic_diskdrive_dict = self.command_to_dict(wmic_diskdrive_raw)

        try:
            wmic_logicaldisk_raw = subprocess.check_output(["wmic", "logicaldisk", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic logicaldisk get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic logicaldisk get * /format:value'.")
        wmic_logicaldisk_dict = self.command_to_dict(wmic_logicaldisk_raw)

        try:
            wmic_partition_raw = subprocess.check_output(["wmic", "partition", "get", "*", "/format:value"])
        except subprocess.CalledProcessError:
            self.logger.critical("Subprocess error calling 'wmic partition get * /format:value'.")
        except:
            self.logger.critical("Generic error calling 'wmic partition get * /format:value'.")
        wmic_partition_dict = self.command_to_dict(wmic_partition_raw)

        # what the offical fuck are you thinking here?!?!
        # need to decide how many items are in wmic_diskdrive_dict...
        # for drive_count in range(0, len(wmic_diskdrive_dict['Name'])):

        if isinstance(wmic_diskdrive_dict['Name'], list):
            num_drives = len(wmic_diskdrive_dict['Name'])
            multiple_drives = True
        elif isinstance(wmic_diskdrive_dict['Name'], str):
            num_drives = 1
            multiple_drives = False
        self.logger.info("Parsing %i drive(s)..." % num_drives)

        for drive_count in range(0, num_drives):
            if (multiple_drives and wmic_diskdrive_dict['TotalHeads'][drive_count]) or (not multiple_drives and wmic_diskdrive_dict['TotalHeads']):

                device_dict = {
                    "disk": None,
                    "model": None,
                    "revision": None,
                    "serial_number": None,
                    "drive_capacity_mb": None,
                    "connection_type": None,
                    "smart_status": None
                }
                if multiple_drives:
                    device_dict['disk'] = wmic_diskdrive_dict['DeviceID'][drive_count]
                    device_dict['model'] = wmic_diskdrive_dict['Caption'][drive_count]
                    device_dict['revision'] = wmic_diskdrive_dict['FirmwareRevision'][drive_count]
                    device_dict['serial_number'] = wmic_diskdrive_dict['SerialNumber'][drive_count]
                    device_dict['drive_capacity_mb'] = int(int(wmic_diskdrive_dict['Size'][drive_count]) / (1024 * 1024))
                    device_dict['smart_status'] = wmic_diskdrive_dict['Status'][drive_count]
                else:
                    device_dict['disk'] = wmic_diskdrive_dict['DeviceID']
                    device_dict['model'] = wmic_diskdrive_dict['Caption']
                    device_dict['revision'] = wmic_diskdrive_dict['FirmwareRevision']
                    device_dict['serial_number'] = wmic_diskdrive_dict['SerialNumber']
                    device_dict['drive_capacity_mb'] = int(int(wmic_diskdrive_dict['Size']) / (1024 * 1024))
                    device_dict['smart_status'] = wmic_diskdrive_dict['Status']

                this_drive_index = wmic_diskdrive_dict['Index'][drive_count]

                if isinstance(wmic_partition_dict['Name'], list):
                    num_partitions = len(wmic_partition_dict['Name'])
                elif isinstance(wmic_partition_dict['Name'], str):
                    num_partitions = 1
                self.logger.info("Parsing %i partition(s)..." % num_partitions)

                partition_list = []
#                 for partition_count in range(0, len(wmic_partition_dict['Name'])):
                for partition_count in range(0, num_partitions):
                    if wmic_partition_dict['DiskIndex'][partition_count] == this_drive_index:
                        # print(" partition disk index matches drive index.")
                        this_partition_size = int(wmic_partition_dict['Size'][partition_count])

                        if isinstance(wmic_logicaldisk_dict['Name'], list):
                            num_logical = len(wmic_logicaldisk_dict['Name'])
                        elif isinstance(wmic_logicaldisk_dict['Name'], str):
                            num_logical = 1
                        self.logger.info("Parsing %i logical disk(s)..." % num_logical)

#                         for logical_count in range(0, len(wmic_logicaldisk_dict['Name'])):
                        for logical_count in range(0, num_logical):
                            if wmic_logicaldisk_dict['Size'][logical_count]:
                                this_logical_size = int(wmic_logicaldisk_dict['Size'][logical_count])
                                diff_part_logical = this_partition_size - this_logical_size
                                if (diff_part_logical > 0) and (diff_part_logical % int(wmic_partition_dict['BlockSize'][partition_count]) == 0) and (diff_part_logical / int(wmic_partition_dict['BlockSize'][partition_count]) < 16):
                                    # print("  partition %s is logical %s" % (wmic_partition_dict['DeviceID'][partition_count], wmic_logicaldisk_dict['DeviceID'][logical_count]))

                                    partition_dict = {
                                        "name": None,
                                        "size": None,
                                        "type": None,
                                        "partition_capacity_mb": None,
                                        "percentage_full": None,
                                        "boot_drive_available_mb": None
                                    }

                                    partition_dict['name'] = wmic_logicaldisk_dict['DeviceID'][logical_count]
                                    partition_dict['size'] = int(int(wmic_partition_dict['Size'][partition_count]) / (1024 * 1024))
                                    partition_dict['partition_capacity_mb'] = int(partition_dict['size'])

                                    temp_partition_used = int(partition_dict['size'] - (int(wmic_logicaldisk_dict['FreeSpace'][logical_count]) / (1024 * 1024)))
                                    partition_dict['percentage_full'] = int(temp_partition_used / int(partition_dict['size']) * 100)

                                    for volume_count in range(0, len(wmic_volume_dict['BootVolume'])):
                                        if (wmic_volume_dict['BootVolume'][volume_count] == "TRUE") and (wmic_volume_dict['DriveLetter'][volume_count] == partition_dict['name']):
                                            partition_dict['type'] = 'boot'
                                            # THIS VALUE IS COMING OUT WRONG!!!
                                            # jamfnation seems to show this is a known issue...
                                            # values reported from the API are correct...
                                            partition_dict['boot_drive_available_mb'] = int(int(wmic_logicaldisk_dict['FreeSpace'][logical_count]) / (1024 * 1024))
                                            partition_dict['name'] = partition_dict['name'] + ' (Boot Partition)'

                                    # attempts to handle incorrect values.
                                    if not partition_dict['boot_drive_available_mb']:
                                        del partition_dict['boot_drive_available_mb']

                                    if not partition_dict['type']:
                                        del partition_dict['type']

                                    partition_list.append(partition_dict)

                self.device_list.append(device_dict)
                self.device_list.append(partition_list)

    def scrub_dict(self, dictionary):
        """
        Recusively removes keys with blank values from provided dictionary
        """
        # https://stackoverflow.com/questions/12118695/efficient-way-to-remove-keys-with-empty-strings-from-a-dict/24688773#24688773

        self.logger.info("%s: activated" % inspect.stack()[0][3])

        new_dict = {}
        for key, value in dictionary.items():
            if isinstance(value, dict):
                value = self.scrub_dict(value)

            if value not in (u'', None, {}):
                new_dict[key] = value
        return new_dict

    def clean_dict(self):
        """
        Makes initial call to scrub_dict
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])
        test = self.scrub_dict(self.computer_dict)
        self.computer_dict = test

    def xml_from_dict(self, data):
        """
        recursively builds xml document from provided dictionary
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        # this is stoopid. have it return the damn string...
        if isinstance(data, list):
            for item in data:
                self.xml_from_dict(item)
        elif isinstance(data, dict):
            for key, value in data.items():
                self.xml_string = self.xml_string + ("<%s>" % key)
                self.xml_from_dict(value)
                self.xml_string = self.xml_string + ("</%s>" % key)
        else:
            self.xml_string = self.xml_string + ("%s" % data)

    def identify_duplicates(self):
        """
        using specific values in computer definition pre-checks for duplicate values and replaces them with randomized string
        """

        # uuid, name, serial, barcode?, mac?

        # loop through possible issue resources, replace resource with string denoting issue...

        # should uuid be here, or just in upload_computer?
        self.logger.info("%s: activated" % inspect.stack()[0][3])

#         duplicate_resources = []

        timenow = str(datetime.datetime.now())
        random_value = str(random.randrange(100, 1000))
        hash_string = timenow + random_value
        hash_time = hashlib.sha224(str(hash_string).encode("utf-8")).hexdigest()
        mini_hash = str(hash_time[-7:-1])
        replacement_string = f"duplicate or blank value found [{mini_hash}]"

        for item in ['udid', 'name', 'serial_number']:
            if self.computer_dict['computer']['general'][item]:
                search_string = self.computer_dict['computer']['general'][item]
            else:
                # just break here...
                # search_string = ""
                self.logger.warning("Blank search value, skipping search. Temp value inserted.")
                self.computer_dict['computer']['general'][item] = "[" + self.computer_dict['computer']['general'][item] + "] " + replacement_string
                self.duplicate_detected = True
                continue

            jss_search_url = self.jss_host + '/JSSResource/computers/match/' + search_string

            headers = {'Accept': 'application/json', }

            response = requests.get(url=jss_search_url, headers=headers, auth=(self.jss_user, self.jss_pwrd))
            # print("Search Status code from request: %s" % response.status_code)
            # print("Search Response text: %r" % response.text)
            # print("Search Response reason: %r" % response.reason)
            # print("Search Response: %r" % response)
            # print("Search Response json: %r" % response.json())

            # response.raise_for_status()

            duplicate_search_results = response.json()

            if len(duplicate_search_results["computers"]) > 1:
                self.logger.warning("Resource conflict, duplicate {}s. Updating record...".format(item))
                self.computer_dict['computer']['general'][item] = "[" + self.computer_dict['computer']['general'][item] + "] " + replacement_string
                self.duplicate_detected = True

            else:
                self.logger.warning("No {} duplicates found.".format(item))

    def mitigate_issues(self, data, length):
        """
        Intended to provide handler to correct specific known issues with JAMF database schema
        """
        # handle uuid issues, serial number issues, cd string length, etc...
        # could be read from a config file

        # version 1, simply remove white space and, if needed, strip off extra characters.
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        if len(data) > length:
            data = re.sub(r'\s+', '', data)

        if len(data) > length:
            data = data[0:length]

        return data

    def upload_computer(self):
        """
        Uploads computer object to JSS, handles errors and PUT/POST switches
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        jss_computer_url = self.jss_host + '/JSSResource/computers/id/0'

        self.logger.info("Submitting XML: %r" % self.output_xml_string)

        try:
            headers = {'Content-Type': 'text/xml', }

            response = requests.post(url=jss_computer_url, headers=headers, data=self.output_xml_string, auth=(self.jss_user, self.jss_pwrd))
            # print("Initial Status code from request: %s" % response.status_code)
            # print("Initial Response text: %r" % response.text)
            # print("Initial Response reason: %r" % response.reason)
            # print("Initial Response: %r" % response)

            if response.status_code == 201:
                self.jss_computer_id = re.findall(r'<id>(.*)<\/id>', response.text)[0]
                self.logger.info("Successfully added {}: {}".format(self.jss_computer_id, self.computer_dict['computer']['general']['ip_address']))
                if self.slack_url:
                    self.slack_message("Added id #" + self.jss_computer_id + " : " + self.computer_dict['computer']['general']['ip_address'], 'new')

            response.raise_for_status()

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

                # should this be at the top of the expect?!?
                error_text = response.text.split("\n")
                for item in error_text:
                    if "Error:" in item:
                        error_message = re.findall(r'\>Error\: (.*)\<', item)[0]

                self.logger.error("HTTP code {}: {} {}".format(response.status_code, "Resource conflict. ", error_message))

                if "Duplicate" in error_message:
                    self.logger.warning("Resource conflict, duplicate UUIDs. Checking count of hosts...")

                    jss_search_url = self.jss_host + '/JSSResource/computers/match/' + self.computer_dict['computer']['general']['udid']

                    headers = {'Accept': 'application/json', }

                    response = requests.get(url=jss_search_url, headers=headers, auth=(self.jss_user, self.jss_pwrd))
                    # print("Search Status code from request: %s" % response.status_code)
                    # print("Search Response text: %r" % response.text)
                    # print("Search Response reason: %r" % response.reason)
                    # print("Search Response: %r" % response)
                    # print("Search Response json: %r" % response.json())

                    # response.raise_for_status()

                    duplicate_search_results = response.json()

                    if len(duplicate_search_results["computers"]) == 1:
                        self.logger.warning("Resource conflict, duplicate UUIDs. Single host, updating record...")

                        for search_item in duplicate_search_results["computers"]:
                            dupl_id = search_item["id"]

                        jss_computer_url = self.jss_host + '/JSSResource/computers/id/' + str(dupl_id)

                        try:
                            headers = {'Content-Type': 'text/xml', }

                            response = requests.put(url=jss_computer_url, headers=headers, data=self.output_xml_string, auth=(self.jss_user, self.jss_pwrd))
                            # print("Put Status code from request: %s" % response.status_code)
                            # print("Put Response text: %r" % response.text)
                            # print("Put Response reason: %r" % response.reason)
                            # print("Put Response: %r" % response)

                            if response.status_code == 201:
                                self.jss_computer_id = re.findall(r'<id>(.*)<\/id>', response.text)[0]
                                self.logger.info("Successfully updated {}: {}".format(self.jss_computer_id, self.computer_dict['computer']['general']['ip_address']))
                                if self.slack_url:
                                    self.slack_message("Updated id #" + self.jss_computer_id + " : " + self.computer_dict['computer']['general']['ip_address'], 'up')

                            response.raise_for_status()

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

                                # should this be at the top of the expect?!?
                                error_text = response.text.split("\n")
                                for item in error_text:
                                    if "Error:" in item:
                                        error_message = re.findall(r'\>Error\: (.*)\<', item)[0]

                                self.logger.error("HTTP code {}: {} {}".format(response.status_code, "Resource conflict. ", error_message))

                    else:
                        self.logger.error("Too many machines sharing duplicate key:value. Exiting.")

            else:
                self.logger.error("HTTP code {}: {}".format(response.status_code, "Generic error."))

        except requests.exceptions.ConnectionError:
            self.logger.error("%s: Error contacting JSS: %s" % (inspect.stack()[0][3], self.jss_host))

        except requests.exceptions.RequestException as this_error:
            self.logger.error("%s: Generic Error: %s" % (inspect.stack()[0][3], this_error))

    def slack_message(self, message, icon):
        """
        Sends completion messages to Slack. Includes duplicate "decorator".
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        if self.duplicate_detected:
            message = message + "  :construction: duplicate flag(s) detected. :construction:"

        if self.jss_computer_id:
            specific_link = self.jss_host + "/computers.html?id=" + self.jss_computer_id + "&o=r"
            message = message + " " + specific_link

        payload = {'text': ':' + icon + ': ' + message, 'username': 'recce ' + self.version, 'icon_emoji': ':' + icon + ':'}

        response = requests.post(self.slack_url, data=json.dumps(payload), headers={'Content-Type': 'application/json'})

        if response.status_code != 200:
            self.logger.error("%s: Possible Slack Error, code: %s" % (inspect.stack()[0][3], response.status_code))

    def display_computer(self):
        """
        Method to display computer data to CLI
        Largely used for debugging.
        """
        self.logger.info("%s: activated" % inspect.stack()[0][3])

        # this could use some improvement...
        def print_dict(data):
            """
            This should not be blank.
            """
            self.logger.info("%s: activated" % inspect.stack()[0][3])

            if isinstance(data, dict):
                for key, value in data.items():
                    print("<%s>" % key)
                    print_dict(value)
                    print("</%s>" % key)
            else:
                print("\t%s" % data)

        print_dict(self.computer_dict)
        print("__________")
        for item in self.device_list:
            print_dict(item)
        print("__________")

        print("\nDevices xml: %s\n" % self.device_xml_string)

        print("Output XML String: %s" % self.xml_string)
