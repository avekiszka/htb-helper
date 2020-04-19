# import modulu
import nmap
import sys, getopt
import subprocess


def print_header(nazwa_uslugi):
    print("-" * 40)
    print("###Port %s otwarty, możesz uruchomić poniższe programy:###" % nazwa_uslugi)

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


def serwisy(adress_hosta, mode):
    if nm[adress_hosta].has_tcp(445):
        if mode == "active":
            print("Port SMB otwarty, uruchamiam program SMBCLIENT")
            run_smbclient(adress_hosta)
            print("Port SMB otwarty, uruchamiam program ENUM4LINUX")
            run_enum4linux(adress_hosta)
        elif mode == "passive":
            print_header("SMB")
            print("nmap --script vuln -p 445 -v %s" % adress_hosta)
            print("smbclient -N -L \\\\\\\\%s\\\\" % adress_hosta)
            print("smbclinet -U "" //%s/<tu wpisz nazwe share drive>" % adress_hosta)
            print("smbmap -H %s -u <nazwa uzytkownika> -p <haslo>" % adress_hosta)
            print("enum4linux %s" % adress_hosta)
    if nm[adress_hosta].has_tcp(80):
        if mode == "active":
            print("Port HTTP otwarty, uruchamiam program XXX")
        if mode == "passive":
            print_header("HTTP")
            print("nmap --script vuln -p 80 -v %s" % adress_hosta)
            print("###Wyszkiwanie plikow i katalogow na serwerze www:###\n","python3 /opt/dirsearch/dirsearch.py -u http://%s/ -f -e html,php,txt,xml -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",sep="" % adress_hosta)
            print("wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://%s/FUZZ.php" % adress_hosta)
            print("\n###Analiza webserwera:###\n")
            print("nikto -host http://%s/" % adress_hosta)
            print("###Sprawdz czy istnieje plik robots.txt###")
            print("###Sprawdz zrodlo strony###")
            print("###Wykorzystaj Burpa###")
    if nm[adress_hosta].has_tcp(8080):
        if mode == "active":
            print("Port HTTP otwarty, uruchamiam program XXX")
        if mode == "passive":
            print_header("HTTP")
            print("nmap --script vuln -p 80 -v %s" % adress_hosta)
            print("###Wyszkiwanie plikow i katalogow na serwerze www:###\n","python3 /opt/dirsearch/dirsearch.py -u http://%s/ -f -e html,php,txt,xml -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",sep="" % adress_hosta)
            print("wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://%s/FUZZ.php" % adress_hosta)
            print("\n###Analiza webserwera:###\n")
            print("nikto -host http://%s/" % adress_hosta)
            print("###Sprawdz czy istnieje plik robots.txt###")
            print("###Sprawdz zrodlo strony###")
            print("###Wykorzystaj Burpa###")
    if nm[adress_hosta].has_tcp(135):
        if mode == "active":
            print("Port RPC otwarty, uruchamiamy program XXX")
        if mode == "passive":
            print_header("RPC")
            print("nmap --script vuln -p 135 -v %s" % adress_hosta)
            print("rpcclient -U \"\" -N %s" % adress_hosta)
    if nm[adress_hosta].has_tcp(389):
        if mode == "active":
            print("Port LDAP otwarty, uruchamiamy program XXX")
        if mode == "passive":
            print_header("LDAP")
            print("nmap --script vuln -p 389 -v %s " % adress_hosta)
            print("\n###Pozyskujemy DN poniższmy poleceniem###\n")
            print("ldapsearch -h %s -x -s base namingcontext" % adress_hosta)
            print("\n###Pozyskane DN wykorzystujemy poniżej. Przykładowe DN 'DC=htb,DC=local'###\n")
            print("ldapsearch -h %s -x -b \"DC=htb,DC=local\"" % adress_hosta)
    if nm[adress_hosta].has_tcp(21):
        if mode == "active":
            print("Port FTP otwarty, uruchamiam program XXX")
        elif mode == "passive":
            print_header("FTP")
            print("nmap --script vuln -p 21 -v %s" % adress_hosta)
            print("Spróbuj anonymous login, jako nazwe uzytkownika uzyj 'anonymous', haslo puste albo cokolwiek")
            print("ftp %s" % adress_hosta)
    if nm[adress_hosta].has_tcp(53):
        if mode == "active":
            print("Not implemented")
        elif mode == "passive":
            print_header("DNS")
            print("nmap --script vuln -p 53 -v %s" % adress_hosta)
            print("###Spróbuj zone transfer:###")
            print("dig AXFR <przykladowan nazwa domeny> @%s" % adress_hosta)
    if nm[adress_hosta].has_udp(53):
        if mode == "active":
            print("not implemented")
        elif mode == "passive":
            print_header("SNMP")
            print("### Spróbuj użyć public community string ###")
            print("snmpwalk -v <version> -c <community string> %s" % adress_hosta)


def main(argv):
    try:
        opts, args = getopt.getopt(argv, "ha:p:")
    except getopt.GetoptError:
        print('nmap_scan.py -i <ip address>')
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print("""\nThis script is designed to help you with recon and enum phase while doing HTB boxes.
            
            Usage:
            python3 htb-helper.py [options] <ip-address>
            
            Options:
            -h      Displays this help message
            -a      Active mode. Runs commands for you, all you need to do is analyze the output.
            -p      Passive mode. Shows you what command you can run, depending on the open port on the device.
            
            Example Usage:
            python3 htb-helper.py -p 10.10.10.178
            
            @avekiszka            
            """)
            sys.exit(0)
        elif opt == "-a":
            adres = arg
            run_ping(adres)
            skaner(adres)
            serwisy(adres, "active")
        elif opt == '-p':
            adres = arg
            run_ping(adres)
            skaner(adres)
            serwisy(adres, "passive")


if __name__ == "__main__":
    main(sys.argv[1:])
