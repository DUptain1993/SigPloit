#!/usr/bin/env python3
'''
5G Information-gathering attack shells (PFCP node discovery, NRF NF discovery).

Each function is a Metasploit-style interactive loop mirroring gtp/info.py:
supports ``show options``, ``set config/target/verbosity``, ``run``, ``back`` and
``exit``.
'''
import sys
import time

import fivegmain
from fiveg.attacks.info import pfcp_node_discovery
from fiveg.attacks.info import nrf_discovery


def _shell(prompt, runner):
    try:
        while True:
            choice = input("\033[37m(\033[0m\033[2;31m%s\033[0m\033[37m)>\033[0m " % prompt)
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
            elif choice.startswith('set listening'):
                fivegmain.listening = choice.split()[2]
            elif choice.startswith('set verbosity'):
                fivegmain.verbosity = int(choice.split()[2])
            elif choice.startswith('set output'):
                fivegmain.output_file = choice.split()[2]
            elif choice == 'run':
                runner(fivegmain.config_file, fivegmain.remote_net,
                       fivegmain.listening, fivegmain.verbosity,
                       fivegmain.output_file)
            elif choice == 'back':
                fivegmain.fiveginfo()
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
        fivegmain.fiveginfo()


def pfcp_discover():
    _shell('pfcp-discover', pfcp_node_discovery.main)


def nrf_discover():
    _shell('nrf-discover', nrf_discovery.main)
