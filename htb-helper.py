# import modulu
import nmap
import sys, getopt
import subprocess


def read_subproc_line(proc):
    while True:
        output = proc.stdout.readline()
        print(output.strip())
        return_code = proc.poll()
        if return_code is not None:
            print('Return Code', return_code)
            for output in proc.stdout.readlines():
                print(output.strip())
            break


def run_ping(ping_address):
    print("#"*10,"PING CHECK START","#"*10,sep="")
    process = subprocess.Popen(['ping', '-c 4', ping_address],stdout=subprocess.PIPE,universal_newlines=True)
    read_subproc_line(process)
    print("#" * 10, "PING CHECK STOP", "#" * 10, sep="")


def run_smbclient(smbclient_address):
    print("#" * 10, "SMBCLIENT START", "#" * 10, sep="")
    process = subprocess.Popen(['smbclient', '-N', '-L', '\\\\\\\\%s\\\\' % smbclient_address],stdout=subprocess.PIPE,universal_newlines=True)
    read_subproc_line(process)
    print("#" * 10, "SMBCLIENT STOP", "#" * 10, sep="")


def run_enum4linux(enum4linux_address):
    print("#" * 10, "ENUM4LINUX START", "#" * 10, sep="")
    process = subprocess.Popen(['enum4linux', enum4linux_address], stdout=subprocess.PIPE, universal_newlines=True)
    read_subproc_line(process)
    print("#" * 10, "ENUM4LINUX STOP", "#" * 10, sep="")

def skaner(adres_do_przeskanowania):
    print("#" * 10, "NMAP SCAN START", "#" * 10, sep="")
    # wczytanie nmapa do pamieci
    global nm
    nm = nmap.PortScanner()
    # start scanu
    print("Uruchamiam NMAP skan")
    nm.scan(adres_do_przeskanowania, arguments='-p- -Pn')
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
    print("#" * 10, "NMAP SCAN STOP", "#" * 10, sep="")


def serwisy(adress_hosta):
    if nm[adress_hosta].has_tcp(445):
        print("Port SMB otwarty, uruchamiam program SMBCLIENT")
        run_smbclient(adress_hosta)
        print("Port SMB otwarty, uruchamiam program ENUM4LINUX")
        run_enum4linux(adress_hosta)


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
            adres = arg
            run_ping(adres)
            skaner(adres)
            serwisy(adres)


if __name__ == "__main__":
    main(sys.argv[1:])
