#!/usr/bin/env python3
'''
5G Main

5G-core (SBA over HTTP/2, and PFCP on N4) attack menus.  Structured to match the
GTP module (gtpmain.py): a set of nested menus plus a Metasploit-style
options/help system shared by the interactive attack shells.
'''
import os
import time
import sys

import fiveg.info
import fiveg.sba
import fiveg.dos
import sigploit

# Shared options, mirroring gtpmain.py.  "target" is an IP/CIDR for the PFCP
# attacks and a host/URL for the SBI attacks; the rest of the parameters come
# from the config file.
config_file = ''
remote_net = ''
listening = True
verbosity = 2
output_file = 'results.csv'


def showOptions(config_file='', remote_net='', listening=True, verbosity=2,
                output_file='results.csv'):
    print('\n     Option                    \t\t\t\t\tValue')
    print('     --------                                                   ------')
    print(('     \033[34mconfig\033[0m     {:<15s} \t\t\t\033[31m%s\033[0m'.format('path to configuration file')) % config_file)
    print(('     \033[34mtarget\033[0m     {:<15s} \t\033[31m%s\033[0m'.format('PFCP: ip/cidr   SBI: host or URL')) % remote_net)
    print(('     \033[34mlistening\033[0m  {:<15s} \t\033[31m%s\033[0m'.format('accepting replies from target, default: True')) % listening)
    print(('     \033[34mverbosity\033[0m  {:<15s} \t\t\t\033[31m%d\033[0m '.format('verbosity level, default: 2')) % verbosity)
    print(('     \033[34moutput\033[0m     {:<15s} \t\t\033[31m%s\033[0m\n '.format('output file, default: results.csv')) % output_file)


def helpmenu():
    print('\n     Command                      Description')
    print('     ---------                   ------------')
    print('     \033[34mshow options\033[0m                display required options to run attack')
    print('     \033[34mset\033[0m                         set a value for an option')
    print("     \033[34mrun\033[0m                         run the exploit")
    print("     \033[34mhelp\033[0m                        display this menu")
    print("     \033[34mback\033[0m                        back to 5G attacks")
    print("     \033[34mexit\033[0m                        exit SigPloit\n")


def fiveginfo():
    os.system('clear')
    print(" \033[31mInformation Gathering\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) PFCP Node Discovery".rjust(25) + "\t\tN4 UPF/SMF discovery, using: Heartbeat / Association Setup")
    print("1) NRF NF Discovery".rjust(22) + "\t\tSBI/HTTP2 NF enumeration via NRF Nnrf_NFDiscovery")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31minfo\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        fiveg.info.pfcp_discover()
    elif choice == "1":
        fiveg.info.nrf_discover()
    elif choice == "back":
        fivegattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-1)')
        time.sleep(1.5)
        fiveginfo()


def fivegsba():
    os.system('clear')
    print(" \033[31mService Based Architecture (SBA)\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) NF Unauthorized Access".rjust(28) + "\tOAuth2 token-enforcement check on an NF SBI service endpoint")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31msba\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        fiveg.sba.nf_access()
    elif choice == "back":
        fivegattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        fivegsba()


def fivegdos():
    os.system('clear')
    print(" \033[31mDenial of Service\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) PFCP Session DoS".rjust(22) + "\t\tN4 session establishment flood / deletion (set mode establish|delete)")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        fiveg.dos.pfcp_session_dos()
    elif choice == "back":
        fivegattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        fivegdos()


def fivegattacks():
    os.system('clear')
    print(" \033[34mChoose From the Below Attack Categories\033[0m ".center(105, "#"))
    print()
    print("0) Information Gathering".rjust(27))
    print("1) Service Based Architecture (SBA)".rjust(38))
    print("2) Denial of Service".rjust(23))
    print()
    print("or type back to return to the main menu".rjust(42))
    print()

    choice = input("\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        fiveginfo()
    elif choice == "1":
        fivegsba()
    elif choice == "2":
        fivegdos()
    elif choice == 'back':
        sigploit.mainMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-2)')
        time.sleep(1.5)
        fivegattacks()


def prep():
    os.system('clear')
    fivegattacks()
