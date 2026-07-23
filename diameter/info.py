#!/usr/bin/env python3
'''
Diameter information-gathering attack shell (Peer Discovery).
'''
import sys
import time

import diametermain
from diameter.attacks.info import peer_discovery


def peer_discover():
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31mpeer-discover\033[0m\033[37m)>\033[0m ")
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
            elif choice.startswith('set listening'):
                diametermain.listening = choice.split()[2].lower() in ('true', '1', 'yes')
            elif choice.startswith('set verbosity'):
                diametermain.verbosity = int(choice.split()[2])
            elif choice.startswith('set output'):
                diametermain.output_file = choice.split()[2]
            elif choice == 'run':
                peer_discovery.main(diametermain.config_file, diametermain.remote_net,
                                    diametermain.listening, diametermain.verbosity,
                                    diametermain.output_file)
            elif choice == 'back':
                diametermain.diameterinfo()
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
        diametermain.diameterinfo()
