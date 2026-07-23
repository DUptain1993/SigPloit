#!/usr/bin/env python3
'''
SIP interception attack shell (INVITE Spoofing).
'''
import sys
import time

import sipmain
from sip.attacks.interception import invite_spoof as invite_spoof_attack


def invite_spoof():
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31minvite-spoof\033[0m\033[37m)>\033[0m ")
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
            elif choice.startswith('set verbosity'):
                sipmain.verbosity = int(choice.split()[2])
            elif choice == 'run':
                invite_spoof_attack.main(sipmain.config_file, sipmain.remote_net,
                                         sipmain.listening, sipmain.verbosity,
                                         sipmain.output_file)
            elif choice == 'back':
                sipmain.sipinterception()
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
        sipmain.sipinterception()
