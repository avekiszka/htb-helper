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


def serwisy(adress_hosta, mode):
    if nm[adress_hosta].has_tcp(445):
        if mode == "active":
            print("Port SMB otwarty, uruchamiam program SMBCLIENT")
            run_smbclient(adress_hosta)
            print("Port SMB otwarty, uruchamiam program ENUM4LINUX")
            run_enum4linux(adress_hosta)
        elif mode == "passive":
            print("-" * 40)
            print("Port SMB otwarty, możesz uruchomić poniższe programy:\n")
            print("nmap --script vuln -p 445 -v %s" % adress_hosta)
            print("smbclient -N -L \\\\\\\\%s\\\\" % adress_hosta)
            print("enum4linux %s" % adress_hosta)
    if nm[adress_hosta].has_tcp(80):
        if mode == "active":
            print("Port HTTP otwarty, uruchamiam program XXX")
        if mode == "passive":
            print("-" * 40)
            print("###Port HTTP otwarty, możesz uruchomić poniższe programy:###\n")
            print("nmap --script vuln -p 80 -v %s" % adress_hosta)
            print("###Wyszkiwanie plikow i katalogow na serwerze www:###\n","python3 /opt/dirsearch/dirsearch.py -u http://%s/ -f -e html,php,txt,xml -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt",sep="" % adress_hosta)
            print("wfuzz -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://%s/FUZZ.php" % adress_hosta)
            print("\n###Analiza webserwera:###\n")
            print("nikto -host http://%s/" % adress_hosta)
    if nm[adress_hosta].has_tcp(135):
        if mode == "active":
            print("Port RPC otwarty, uruchamiamy program XXX")
        if mode == "passive":
            print("-" * 40)
            print("###Port RPC otwarty, możesz uruchomić poniższe programy:###\n")
            print("nmap --script vuln -p 135 -v %s" % adress_hosta)
            print("rpcclient -U \"\" -N %s" % adress_hosta)
    if nm[adress_hosta].has_tcp(389):
        if mode == "active":
            print("Port LDAP otwarty, uruchamiamy program XXX")
        if mode == "passive":
            print("-"*40)
            print("###Port LDAP otwarty, możesz uruchomić poniższe programy:###\n")
            print("nmap --script vuln -p 389 -v %s " % adress_hosta)
            print("\n###Pozyskujemy DN poniższmy poleceniem###\n")
            print("ldapsearch -h %s -x -s base namingcontext" % adress_hosta)
            print("\n###Pozyskane DN wykorzystujemy poniżej. Przykładowe DN 'DC=htb,DC=local'###\n")
            print("ldapsearch -h %s -x -b \"DC=htb,DC=local\"" % adress_hosta)

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
