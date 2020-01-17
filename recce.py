#!/usr/bin/python
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

# recce.py #####################################################################
#
# A Python script to
#
#
#    1.0.0      2019.07.16     Initial version. tjm
#
#    1.0.1      2019.07.22      Adjusted server url handling. tjm
#
#    1.0.2      2020.01.06      Added jamfcloud accomodation. tjm
#
################################################################################
################################################################################
#
#
#
#
# Still to do:
#   bus speed
#   cache size? which cache?!?
#   service pack?
#   AD Status
#
#
#
# Defend dictionary against additions
#
#
# test if no value, missing optical drive for instance...
#
#
#
#
# pylint -ry -f colorized --max-line-length=240 recce.py
#
#
# pyinstaller --onefile --version-file file_version_info_recce.txt recce.py
#
#
#  -c, --console, --nowindowed
#     Open a console window for standard i/o (default)
#  -w, --windowed, --noconsole
#     Windows and Mac OS X: do not provide a console window for standard i/o. On Mac OS X this also triggers building an OS X .app bundle. This option is ignored in *NIX systems.
#
################################################################################


# insert imports
from __future__ import division
from __future__ import print_function

import argparse
import logging
import os
import pathlib
import platform
import sys

import jss_login
if platform.system() == 'Darwin':
    pass
elif platform.system() == 'Windows':
    import windows_computer
elif platform.system() == 'Linux':
    pass


__version__ = '1.0.2'


def main():
    """
    This should not be blank.
    """

    logo = """
     /_ _/ /_ _/   University of Utah
      _/    _/    Marriott Library
     _/    _/    Client Platform Services, Mac Group
    _/    _/   https://apple.lib.utah.edu/
     _/_/    https://github.com/univ-of-utah-marriott-library-apple


        """
    desc = "Add unmanaged computers and inventory information to JAMF."

    parser = argparse.ArgumentParser(description=logo+desc, formatter_class=argparse.RawTextHelpFormatter)

    parser.add_argument('-t', '--testmode', action="store_true", default=False, help='Test mode.')
    parser.add_argument('-s', '--system_specific', action="store_true", default=False, help='Writes configuration file to system specific location, instead of adjacent to script.')
    parser.add_argument('-v', '--version', action='version', version='%(prog)s ' + __version__)
    parser.add_argument('-m', '--manual_login', help='Force manual login, bypass existing configuration file.', action="store_true", default=False)
    parser.add_argument('-q', '--quit_config', help='If the configuration file is missing, quit.', action="store_true", default=False)

    args = parser.parse_args()

    if args.testmode:
        print(args)

    executable_name = os.path.basename(sys.argv[0])

    # this is duplicated from the login module, not elegant but 1.0 worthy.
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
                #
                # Is this a bailout error?
                print(exception_message)
            config_name = 'edu.scl.utah.' + '_'.join(split_filename) + '.ini'
        else:
            config_name = 'edu.scl.utah.' + filename + '.ini'

    except Exception as exception_message:
        print("Error creating config_name [%s]. %s" % (executable_name, exception_message))

    local_path = pathlib.Path(os.path.dirname(os.path.realpath(sys.argv[0])), config_name)

    if os.path.exists(local_path):
        log_path = os.path.join(os.path.dirname(os.path.realpath(sys.argv[0])), 'recce_' + __version__ + '.log')

    else:
        if platform.system() == 'Darwin':
            log_path = os.path.join('recce_' + __version__ + '.log')
        elif platform.system() == 'Windows':
            log_path = os.path.join(os.environ['TEMP'], 'recce_' + __version__ + '.log')

    logging.basicConfig(filename=log_path, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logger = logging.getLogger(__name__)

    logger.info("recce launched.")
    logger.info("recce version {}".format(__version__))
    logger.info("jss_login version {}".format(jss_login.__version__))

    if platform.system() == 'Darwin':
        pass
    elif platform.system() == 'Windows':
        logger.info("windows_computer version {}".format(windows_computer.__version__))
    elif platform.system() == 'Linux':
        pass

    this_login = jss_login.Login(logger, args)
    jamf_username, jamf_password, jamf_hostname, slack_url = this_login.validated_creds()

    if platform.system() == 'Darwin':
        pass
    elif platform.system() == 'Windows':
        this_computer = windows_computer.Computer(logger, jamf_username, jamf_password, jamf_hostname, slack_url, __version__)
        this_computer.upload_computer()
    elif platform.system() == 'Linux':
        pass


if __name__ == '__main__':
    main()
