#!/usr/bin/env python3
'''
Diameter Main

4G/LTE Diameter (S6a) attack menus. Structured to match the GTP/5G modules:
nested menus plus a Metasploit-style options/help system shared by the
interactive attack shells.
'''
import os
import time
import sys

import diameter.info
import diameter.tracking
import diameter.interception
import diameter.dos
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
    print(('     \033[34mtarget\033[0m     {:<15s} \t\033[31m%s\033[0m'.format('HSS/peer ip, hostname or CIDR')) % remote_net)
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
    print("     \033[34mback\033[0m                        back to Diameter attacks")
    print("     \033[34mexit\033[0m                        exit SigPloit\n")


def diameterinfo():
    os.system('clear')
    print(" \033[31mInformation Gathering\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) Peer Discovery".rjust(20) + "\t\tHSS/MME/DRA discovery via CER/CEA, reports S6a support")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31minfo\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        diameter.info.peer_discover()
    elif choice == "back":
        diameterattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        diameterinfo()


def diametertracking():
    os.system('clear')
    print(" \033[31mLocation Tracking\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) Authentication Info (AIR)".rjust(30) + "\tRetrieve EPS auth vectors for an IMSI, AuthInfo.cnf")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31mtracking\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        diameter.tracking.auth_info()
    elif choice == "back":
        diameterattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        diametertracking()


def diameterinterception():
    os.system('clear')
    print(" \033[31mInterception\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) Update Location (ULR)".rjust(26) + "\t\tRegister attacker MME for the subscriber, UpdateLocation.cnf")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31minterception\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        diameter.interception.update_location()
    elif choice == "back":
        diameterattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        diameterinterception()


def diameterdos():
    os.system('clear')
    print(" \033[31mDenial of Service\033[0m ".center(105, "#"))
    print(" \033[34mSelect an Attack from the below\033[0m ".center(105, "#"))
    print()
    print("   Attacks".rjust(10) + "\t\t\t\tDescription")
    print("   --------                             ------------")
    print("0) Subscriber DoS".rjust(18) + "\t\tCancel-Location / Purge-UE, set mode cancel|purge, SubscriberDoS.cnf")
    print()
    print("or type back to go back to Attacks Menu".rjust(42))

    choice = input("\033[37m(\033[0m\033[2;31mdos\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        diameter.dos.subscriber_dos()
    elif choice == "back":
        diameterattacks()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0)')
        time.sleep(1.5)
        diameterdos()


def diameterattacks():
    os.system('clear')
    print(" \033[34mChoose From the Below Attack Categories\033[0m ".center(105, "#"))
    print()
    print("0) Information Gathering".rjust(27))
    print("1) Location Tracking".rjust(23))
    print("2) Interception".rjust(17))
    print("3) Denial of Service".rjust(23))
    print()
    print("or type back to return to the main menu".rjust(42))
    print()

    choice = input("\033[37m(\033[0m\033[2;31mattacks\033[0m\033[37m)>\033[0m ")
    if choice == "0":
        diameterinfo()
    elif choice == "1":
        diametertracking()
    elif choice == "2":
        diameterinterception()
    elif choice == "3":
        diameterdos()
    elif choice == 'back':
        sigploit.mainMenu()
    else:
        print('\n\033[31m[-]Error:\033[0m Please Enter a Valid Choice (0-3)')
        time.sleep(1.5)
        diameterattacks()


def prep():
    os.system('clear')
    diameterattacks()
