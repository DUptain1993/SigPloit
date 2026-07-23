#!/usr/bin/env python3
'''
5G SBA attack shell (NF unauthorized-access / OAuth2 enforcement check).
'''
import sys
import time

import fivegmain
from fiveg.attacks.sba import nf_access as nf_access_attack


def nf_access():
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31mnf-access\033[0m\033[37m)>\033[0m ")
            if choice == 'help' or choice == '?':
                fivegmain.helpmenu()
            elif choice == 'show options':
                fivegmain.showOptions(fivegmain.config_file, fivegmain.remote_net,
                                      fivegmain.listening, fivegmain.verbosity,
                                      fivegmain.output_file)
            elif choice.startswith('set config'):
                fivegmain.config_file = choice.split()[2]
            elif choice.startswith('set target'):
                fivegmain.remote_net = choice.split()[2]
            elif choice.startswith('set verbosity'):
                fivegmain.verbosity = int(choice.split()[2])
            elif choice == 'run':
                nf_access_attack.main(fivegmain.config_file, fivegmain.remote_net,
                                      fivegmain.listening, fivegmain.verbosity,
                                      fivegmain.output_file)
            elif choice == 'back':
                fivegmain.fivegsba()
                return
            elif choice == 'exit':
                print('\nYou are now exiting SigPloit...')
                time.sleep(1)
                sys.exit(0)
            else:
                print('\033[31m[-]Error:\033[0m invalid command, choose one of the below commands\n')
                fivegmain.helpmenu()
    except SystemExit:
        raise
    except Exception as e:
        print("\033[31m[-]Error:\033[0m attack failed to launch, " + str(e))
        time.sleep(2)
        fivegmain.fivegsba()
