#import modulu
import nmap
import sys, getopt


def skaner(adres):
    #wczytanie nmapa do pamieci
    nm = nmap.PortScanner()
    #start scanu
    nm.scan(adres)
    #wyswietlenie rezultatu
    for host in nm.all_hosts():
        print('-'*40)
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s ' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('-'*10)
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "hi:")
    except getopt.GetoptError:
        print('nmap_scan.py -i <ip address>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print('nmap_scan.py -i <ip address>')
            sys.exit(0)
        elif opt in "-i":
            adress = arg
            skaner(adress)

if __name__ == "__main__":
    main(sys.argv[1:])