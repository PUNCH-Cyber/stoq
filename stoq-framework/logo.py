#   Copyright 2014-2015 PUNCH Cyber Analytics Group
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

"""
stoQ Framework

"""

import sys
import random

from stoq.core import __version__


def print_logo():
    logo = []

    logo.append("""
    .------..------..------..------.
    |S.--. ||T.--. ||O.--. ||Q.--. |
    | :/\: || :/\: || :/\: || (\/) |
    | :\/: || (__) || :\/: || :\/: |
    | '--'S|| '--'T|| '--'O|| '--'Q|
    `------'`------'`------'`------'

          Analysis. Simplified.
                 v{}
    """.format(__version__))

    logo.append("""
          *******                               * ***
        *       ***      *                    *  ****
       *         **     **                   *  *  ***
       **        *      **                  *  **   ***
        ***           ********    ****     *  ***    ***
       ** ***        ********    * ***  * **   **     **
        *** ***         **      *   ****  **   **     **
          *** ***       **     **    **   **   **     **
            *** ***     **     **    **   **   **     **
              ** ***    **     **    **   **   **     **
               ** **    **     **    **    **  ** *** **
                * *     **     **    **     ** *   ****
      ***        *      **      ******       ***     ***
     *  *********        **      ****         ******* **
    *     *****                                 ***   **
    *                                                 **
     **                                               *
                                                     *
                                                    *
                    Analysis. Simplified.
                          v{}
    """.format(__version__))

    logo.append("""
     .d8888b.  888             .d88888b.
    d88P  Y88b 888            d88P" "Y88b
    Y88b.      888            888     888
     "Y888b.   888888 .d88b.  888     888
        "Y88b. 888   d88""88b 888     888
          "888 888   888  888 888 Y8b 888
    Y88b  d88P Y88b. Y88..88P Y88b.Y8b88P
     "Y8888P"   "Y888 "Y88P"   "Y888888"
                                     Y8b
            Analysis. Simplified.
                  v{}
    """.format(__version__))

    logo.append("""
     _______ _______  _____   _____
     |______    |    |     | |   __|
     ______|    |    |_____| |____\|

           Analysis. Simplified.
                 v{}
    """.format(__version__))

    logo.append("""
      .--.--.       ___                  ,----..      
     /  /    '.   ,--.'|_               /   /   \     
    |  :  /`. /   |  | :,'    ,---.    /   .     :    
    ;  |  |--`    :  : ' :   '   ,'\  .   /   ;.  \   
    |  :  ;_    .;__,'  /   /   /   |.   ;   /  ` ;   
     \  \    `. |  |   |   .   ; ,. :;   |  ; \ ; |   
      `----.   \:__,'| :   '   | |: :|   :  | ; | '   
      __ \  \  |  '  : |__ '   | .; :.   |  ' ' ' :   
     /  /`--'  /  |  | '.'||   :    |'   ;  \; /  |   
    '--'.     /   ;  :    ; \   \  /  \   \  ',  . \  
      `--'---'    |  ,   /   `----'    ;   :      ; | 
                   ---`-'               \   \ .'`--"  
                                         `---`        
                Analysis. Simplified.
                      v{}
    """.format(__version__))

    logo.append("""
     _______ _________ _______  _______ 
    (  ____ \\__   __/(  ___  )(  ___  )
    | (    \/   ) (   | (   ) || (   ) |
    | (_____    | |   | |   | || |   | |
    (_____  )   | |   | |   | || |   | |
          ) |   | |   | |   | || | /\| |
    /\____) |   | |   | (___) || (_\ \ |
    \_______)   )_(   (_______)(____\/_)

            Analysis. Simplified.
                  v{}
    """.format(__version__))

    logo.append("""
      _________  __          ________   
     /   _____/_/  |_  ____  \_____  \  
     \_____  \ \   __\/  _ \  /  / \  \ 
     /        \ |  | (  <_> )/   \_/.  \ 
    /_______  / |__|  \____/ \_____\ \_/ 
            \/                      \__>

            Analysis. Simplified.
                  v{}
    """.format(__version__))

    logo.append("""
               ___                       
              (   )                      
        .--.   | |_      .--.    .--.    
      /  _  \ (   __)   /    \  /    \   
     . .' `. ; | |     |  .-. ;|  .-. '  
     | '   | | | | ___ | |  | || |  | |  
     _\_`.(___)| |(   )| |  | || |  | |  
    (   ). '.  | | | | | |  | || |  | |  
     | |  `\ | | ' | | | '  | || '  | |  
     ; '._,' ' ' `-' ; '  `-' /' `-'  |  
      '.___.'   `.__.   `.__.'  `._ / |  
                                    | |  
                                   (___) 

            Analysis. Simplified.
                  v{}
    """.format(__version__))

    logo.append("""
    ███████╗████████╗ ██████╗  ██████╗ 
    ██╔════╝╚══██╔══╝██╔═══██╗██╔═══██╗
    ███████╗   ██║   ██║   ██║██║   ██║
    ╚════██║   ██║   ██║   ██║██║▄▄ ██║
    ███████║   ██║   ╚██████╔╝╚██████╔╝
    ╚══════╝   ╚═╝    ╚═════╝  ╚══▀▀═╝ 

           Analysis. Simplified.
                 v{}
    """.format(__version__))

    logo.append("""
       ▄████████     ███      ▄██████▄  ████████▄   
      ███    ███ ▀█████████▄ ███    ███ ███    ███  
      ███    █▀     ▀███▀▀██ ███    ███ ███    ███  
      ███            ███   ▀ ███    ███ ███    ███  
    ▀███████████     ███     ███    ███ ███    ███  
             ███     ███     ███    ███ ███    ███  
       ▄█    ███     ███     ███    ███ ███  ▀ ███  
     ▄████████▀     ▄████▀    ▀██████▀   ▀██████▀▄█ 

                   Analysis. Simplified.
                         v{}
    """.format(__version__))

    sys.stdout.flush()
    try:
        print(random.choice(logo))
    except:
        print(logo[3])
    sys.stdout.flush()
