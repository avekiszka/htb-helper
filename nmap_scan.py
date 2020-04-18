# import modulu
import nmap
import sys, getopt
import subprocess


def run_ping(adress):
    process = subprocess.Popen(['ping', '-c 4', adress],stdout=subprocess.PIPE,universal_newlines=True)
    while True:
        output = process.stdout.readline()
        print(output.strip())
        return_code = process.poll()
        if return_code is not None:
            print('Return Code', return_code)
            for output in process.stdout.readlines():
                print(output.strip())
            break

def skaner(adres):
    # wczytanie nmapa do pamieci
    global nm
    nm = nmap.PortScanner()
    # start scanu
    print("Uruchamiam NMAP skan")
    nm.scan(adres)
    # wyswietlenie rezultatu
    for host in nm.all_hosts():
        print('-'*40)
        print('Host : %s (%s)' % (host, nm[host].hostname()))
        print('State : %s ' % nm[host].state())
        for proto in nm[host].all_protocols():
            print('-'*10)
            print('Protocol : %s' % proto)
            lport = nm[host][proto].keys()
            for port in lport:
                print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))


def serwisy(adress):
    if nm[adress].has_tcp(445):
        print("Port SMB otwarty, uruchamiam program SMBCLIENT")


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
            skaner(arg)
            serwisy(arg)
            run_ping(arg)


if __name__ == "__main__":
    main(sys.argv[1:])