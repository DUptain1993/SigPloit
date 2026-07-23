#!/usr/bin/env python3
'''
SIP information-gathering attack shells (OPTIONS Discovery, REGISTER Enumeration).
'''
import sys
import time

import sipmain
from sip.attacks.info import options_discovery
from sip.attacks.info import register_enum


def _shell(prompt, runner, back_menu):
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31m%s\033[0m\033[37m)>\033[0m " % prompt)
            if choice == 'help' or choice == '?':
                sipmain.helpmenu()
            elif choice == 'show options':
                sipmain.showOptions(sipmain.config_file, sipmain.remote_net,
                                    sipmain.listening, sipmain.verbosity,
                                    sipmain.output_file)
            elif choice.startswith('set config'):
                sipmain.config_file = choice.split()[2]
            elif choice.startswith('set target'):
                sipmain.remote_net = choice.split()[2]
            elif choice.startswith('set listening'):
                sipmain.listening = choice.split()[2].lower() in ('true', '1', 'yes')
            elif choice.startswith('set verbosity'):
                sipmain.verbosity = int(choice.split()[2])
            elif choice.startswith('set output'):
                sipmain.output_file = choice.split()[2]
            elif choice == 'run':
                runner(sipmain.config_file, sipmain.remote_net, sipmain.listening,
                       sipmain.verbosity, sipmain.output_file)
            elif choice == 'back':
                back_menu()
                return
            elif choice == 'exit':
                print('\nYou are now exiting SigPloit...')
                time.sleep(1)
                sys.exit(0)
            else:
                print('\033[31m[-]Error:\033[0m invalid command, choose one of the below commands\n')
                sipmain.helpmenu()
    except SystemExit:
        raise
    except Exception as e:
        print("\033[31m[-]Error:\033[0m attack failed to launch, " + str(e))
        time.sleep(2)
        back_menu()


def options_discover():
    _shell('options-discover', options_discovery.main, sipmain.sipinfo)


def register_enumerate():
    _shell('register-enum', register_enum.main, sipmain.sipinfo)
