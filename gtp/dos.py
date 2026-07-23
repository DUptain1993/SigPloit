#!/usr/bin/env python3
'''
GTPv2 Denial of Service attack shells.

Wires the (previously orphaned) massive_dos and user_dos attacks into the GTP
menu, using the same Metasploit-style shell as the other GTP attacks. The
underlying attacks expose an OptionParser main(argv); the shells build that argv
from the shared gtpmain options.
'''

import sys
import time
import gtpmain

from attacks.dos import massive_dos
from attacks.dos import user_dos


def _dos_shell(prompt, attack):
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31m%s\033[0m\033[37m)>\033[0m " % prompt)
            if choice == 'help' or choice == '?':
                gtpmain.helpmenu()
            elif choice == 'show options':
                gtpmain.showOptions(gtpmain.config_file, gtpmain.remote_net,
                                    gtpmain.listening, gtpmain.verbosity,
                                    gtpmain.output_file)
            elif 'set config' in choice:
                gtpmain.config_file = choice.split()[2]
            elif 'set target' in choice:
                gtpmain.remote_net = choice.split()[2]
            elif 'set listening' in choice:
                gtpmain.listening = choice.split()[2]
            elif 'set verbosity' in choice:
                gtpmain.verbosity = int(choice.split()[2])
            elif 'run' in choice:
                argv = ['-c', gtpmain.config_file]
                if gtpmain.remote_net:
                    argv += ['-r', gtpmain.remote_net]
                if gtpmain.listening and str(gtpmain.listening).lower() in ('true', '1', 'yes'):
                    argv += ['-l']
                attack.main(argv)
            elif 'back' in choice:
                gtpmain.gtpdos()
                return
            elif 'exit' in choice:
                print('\nYou are now exiting SigPloit...')
                time.sleep(1)
                sys.exit(0)
            else:
                print('\033[31m[-]Error:\033[0m invalid command, choose one of the below commands\n')
                gtpmain.helpmenu()
    except SystemExit:
        raise
    except Exception as e:
        print("\033[31m[-]Error:\033[0m DoS attack failed to launch, " + str(e))
        time.sleep(2)
        gtpmain.gtpdos()


def mdos():
    _dos_shell('massive-dos', massive_dos)


def udos():
    _dos_shell('user-dos', user_dos)
