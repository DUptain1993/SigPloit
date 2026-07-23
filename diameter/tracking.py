#!/usr/bin/env python3
'''
Diameter Location Tracking attack shell (Authentication-Information-Request).
'''
import sys
import time

import diametermain
from diameter.attacks.tracking import auth_info as auth_info_attack


def auth_info():
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31mair\033[0m\033[37m)>\033[0m ")
            if choice == 'help' or choice == '?':
                diametermain.helpmenu()
            elif choice == 'show options':
                diametermain.showOptions(diametermain.config_file, diametermain.remote_net,
                                         diametermain.listening, diametermain.verbosity,
                                         diametermain.output_file)
            elif choice.startswith('set config'):
                diametermain.config_file = choice.split()[2]
            elif choice.startswith('set target'):
                diametermain.remote_net = choice.split()[2]
            elif choice.startswith('set verbosity'):
                diametermain.verbosity = int(choice.split()[2])
            elif choice == 'run':
                auth_info_attack.main(diametermain.config_file, diametermain.remote_net,
                                      diametermain.listening, diametermain.verbosity,
                                      diametermain.output_file)
            elif choice == 'back':
                diametermain.diametertracking()
                return
            elif choice == 'exit':
                print('\nYou are now exiting SigPloit...')
                time.sleep(1)
                sys.exit(0)
            else:
                print('\033[31m[-]Error:\033[0m invalid command, choose one of the below commands\n')
                diametermain.helpmenu()
    except SystemExit:
        raise
    except Exception as e:
        print("\033[31m[-]Error:\033[0m attack failed to launch, " + str(e))
        time.sleep(2)
        diametermain.diametertracking()
