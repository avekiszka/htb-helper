# htb-helper
This script is designed to help you with recon and enum phase while doing HTB boxes.
            
            Usage:
            python3 htb-helper.py [options] <ip-address>
            
            Options:
            -h      Displays this help message
            -a      Active mode. Runs commands for you, all you need to do is analyze the output. ***ALPHA***
            -p      Passive mode. Shows you what command you can run, depending on the open port on the device. ***BETA***
            
            Example Usage:
            python3 htb-helper.py -p 10.10.10.178
            
            @avekiszka 
