#!/usr/bin/env python3
'''
SIP Main

4G IMS/VoLTE SIP access-layer attack menus. Structured to match the GTP/
Diameter/5G modules: nested menus plus a Metasploit-style options/help system
shared by the interactive attack shells.
'''
import os
import time
import sys

import sip.info
import sip.interception
import sip.dos
import sigploit

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
    print(('     \033[34mtarget\033[0m     {:<15s} \t\033[31m%s\033[0m'.format('SIP peer/registrar ip, hostname or CIDR')) % remote_net)
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
    print("     \033[34mback\033[0m                        back to SIP attacks")
    print("     \033[34mexit\033[0m                        exit SigPloit\n")


def sipinfo():
    os.system('clear')
    print(" \033[31mInformation Gathering\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) OPTIONS Discovery".rjust(22) + "\t\tIMS core (P-CSCF/S-CSCF) node discovery via SIP OPTIONS")
    print("1) REGISTER Enumeration".rjust(25) + "\t\tSubscriber/extension enumeration via REGISTER challenge oracle")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31minfo\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        sip.info.options_discover()
    elif choice == "1":
        sip.info.register_enumerate()
    elif choice == "back":
        sipattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-1)')
        time.sleep(1.5)
        sipinfo()


def sipinterception():
    os.system('clear')
    print(" \033[31mInterception\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) INVITE Spoofing".rjust(20) + "\t\tCaller identity spoofing via forged From/P-Asserted-Identity, InviteSpoof.cnf")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31minterception\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        sip.interception.invite_spoof()
    elif choice == "back":
        sipattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        sipinterception()


def sipdos():
    os.system('clear')
    print(" \033[31mDenial of Service\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) INVITE Flood".rjust(17) + "\t\tCall-state exhaustion via repeated unique INVITE requests, InviteFlood.cnf")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        sip.dos.invite_flood()
    elif choice == "back":
        sipattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        sipdos()


def sipattacks():
    os.system('clear')
    print(" \033[34mChoose From the Below Attack Categories\033[0m ".center(105, "#"))
    print()
    print("0) Information Gathering".rjust(27))
    print("1) Interception".rjust(17))
    print("2) Denial of Service".rjust(23))
    print()
    print("or type back to return to the main menu".rjust(42))
    print()

    choice = input("\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        sipinfo()
    elif choice == "1":
        sipinterception()
    elif choice == "2":
        sipdos()
    elif choice == 'back':
        sigploit.mainMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-2)')
        time.sleep(1.5)
        sipattacks()


def prep():
    os.system('clear')
    sipattacks()
