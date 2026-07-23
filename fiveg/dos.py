#!/usr/bin/env python3
'''
5G DoS attack shell (PFCP N4 session establishment flood / deletion).

Adds a ``set mode establish|delete`` option on top of the standard shell.
'''
import sys
import time

import fivegmain
from fiveg.attacks.dos import pfcp_session_dos as pfcp_session_dos_attack

_mode = 'establish'


def pfcp_session_dos_shell():
    global _mode
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31mpfcp-dos\033[0m\033[37m)>\033[0m ")
            if choice == 'help' or choice == '?':
                fivegmain.helpmenu()
                print("     \033[34mset mode\033[0m                    establish | delete (default: establish)")
            elif choice == 'show options':
                fivegmain.showOptions(fivegmain.config_file, fivegmain.remote_net,
                                      fivegmain.listening, fivegmain.verbosity,
                                      fivegmain.output_file)
                print('     \033[34mmode\033[0m       establish|delete \t\t\t\033[31m%s\033[0m' % _mode)
            elif choice.startswith('set config'):
                fivegmain.config_file = choice.split()[2]
            elif choice.startswith('set target'):
                fivegmain.remote_net = choice.split()[2]
            elif choice.startswith('set verbosity'):
                fivegmain.verbosity = int(choice.split()[2])
            elif choice.startswith('set mode'):
                m = choice.split()[2]
                if m in ('establish', 'delete'):
                    _mode = m
                else:
                    print('\033[31m[-]Error:\033[0m mode must be establish or delete')
            elif choice == 'run':
                pfcp_session_dos_attack.main(fivegmain.config_file, fivegmain.remote_net,
                                             fivegmain.listening, fivegmain.verbosity,
                                             fivegmain.output_file, mode=_mode)
            elif choice == 'back':
                fivegmain.fivegdos()
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
        fivegmain.fivegdos()


# name used by fivegmain
pfcp_session_dos = pfcp_session_dos_shell
