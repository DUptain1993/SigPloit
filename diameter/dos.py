#!/usr/bin/env python3
'''
Diameter DoS attack shell (Cancel-Location / Purge-UE).

Adds a ``set mode cancel|purge`` option on top of the standard shell.
'''
import sys
import time

import diametermain
from diameter.attacks.dos import subscriber_dos as subscriber_dos_attack

_mode = 'cancel'


def subscriber_dos():
    global _mode
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31ms6a-dos\033[0m\033[37m)>\033[0m ")
            if choice == 'help' or choice == '?':
                diametermain.helpmenu()
                print("     \033[34mset mode\033[0m                    cancel | purge (default: cancel)")
            elif choice == 'show options':
                diametermain.showOptions(diametermain.config_file, diametermain.remote_net,
                                         diametermain.listening, diametermain.verbosity,
                                         diametermain.output_file)
                print('     \033[34mmode\033[0m       cancel|purge \t\t\t\033[31m%s\033[0m' % _mode)
            elif choice.startswith('set config'):
                diametermain.config_file = choice.split()[2]
            elif choice.startswith('set target'):
                diametermain.remote_net = choice.split()[2]
            elif choice.startswith('set verbosity'):
                diametermain.verbosity = int(choice.split()[2])
            elif choice.startswith('set mode'):
                m = choice.split()[2]
                if m in ('cancel', 'purge'):
                    _mode = m
                else:
                    print('\033[31m[-]Error:\033[0m mode must be cancel or purge')
            elif choice == 'run':
                subscriber_dos_attack.main(diametermain.config_file, diametermain.remote_net,
                                           diametermain.listening, diametermain.verbosity,
                                           diametermain.output_file, mode=_mode)
            elif choice == 'back':
                diametermain.diameterdos()
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
        diametermain.diameterdos()
