import nmap
import sys
import argparse


# Arugments:
# all protocols (default)
# TCP scan
# UDP scan
# Operating system scan
# check if the host is up

# ports that will be scaned.
ports = '1-65535'

try:
    nm = nmap.PortScanner()
except nmap.PortScannerError:
    print('Nmap not found', sys.exc_info()[0])
    sys.exit(0)
except:
    print("Unexpected error:", sys.exc_info()[0])
    sys.exit(0)


def getStarted(ip, ports='1-65535'):
    nm.scan(ip, ports, sudo=True)
    nm.all_hosts()
    nm[ip].all_protocols()


def allProtocals():
    for host in nm.all_hosts():
        print('----------------------------------------------------')
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        # call all protocols
        tcp_scan(host)
        udp_scan(host)


def tcp_scan(host):
    print('Protocol : TCP')
    for port in nm[host].all_tcp():
        protocol_name = "tcp"
        print(
            f"{nm[host][protocol_name][port]['name']}\tport : {port}\tstate : {nm[host][protocol_name][port]['state']}")
    print('----------')


def tcp_new_scan(ip):
    print('Protocol : TCP (DUMP)')
    protocol_name = 'tcp'
    nm.scan(ip, ports, arguments='-v -sT')
    for host in nm.all_hosts():
        nm[host].all_protocols()
        for port in nm[host][protocol_name]:
            print(
                f"{nm[host][protocol_name][port]['name']}\tport : {port}\tstate : {nm[host][protocol_name][port]['state']}")
        print('----------')


def udp_scan(host):
    print('Protocol : UDP')
    protocol_name = 'udp'
    for host in nm.all_hosts():
        nm.scan(host, ports, arguments='-sU', sudo=True)
        nm[host].all_udp()
        for port in nm[host][protocol_name]:
            print(
                f"{nm[host][protocol_name][port]['name']}\tport : {port}\t\tstate : {nm[host][protocol_name][port]['state']}")

        print('----------')


def dump_scan():
    print('Protocol : TCP (DUMP)')
    for host in nm.all_hosts():
        nm.scan(host, ports, arguments='-v -sT')
        nm[host].all_protocols()
        protocol_name = 'tcp'

        for port in nm[host][protocol_name]:
            print(
                f"{nm[host][protocol_name][port]['name']}\tport : {port}\tstate : {nm[host][protocol_name][port]['state']}")
        print('----------')


def os_scan(host):
    for host in nm.all_hosts():
        scan = nm.scan(host, ports, arguments='-O', sudo=True)
        print(f"------- OS SCAN -------")
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        print(f"Operation System : {scan['scan'][host]['osmatch'][0]['name']}")
        print(f"-------------------------")


def ping_scan(host):
    nm.scan(host, ports, arguments='-n -Pn')
    for host in nm.all_hosts():
        print(f"------- PING SCAN -------")
        print(f"Host : {host} ({nm[host].hostname()})")
        print(f"State : {nm[host].state()}")
        print(f"-------------------------")


def options(host, options):
    print(nm.scan(host, ports, arguments=options))


def getArgs():
    parser = argparse.ArgumentParser(
        description='nmap scanning from python script. By Mutlaq Aldhbuiub @ TVTC')
    parser.add_argument('--ip', type=str, help="set the target ip address")
    parser.add_argument('--protocol', type=str,
                        help="set a protocol such as (default)TCP, UDP")
    parser.add_argument('--options', type=str,
                        help="get operating system information \n --options=os, --options=ping")
    args = vars(parser.parse_args())

    # only ip address:
    if args['ip'] is not None and args['protocol'] is None and args['options'] is None:
        ip = args['ip']
        getStarted(ip, ports)
        tcp_new_scan(ip)

    # ip with protocol:
    if args['ip'] is not None and args['protocol'] is not None and args['options'] is None:
        ip = args['ip']
        getStarted(ip, ports)
        if args['protocol'] == 'tcp':
            tcp_new_scan(ip)
        elif args['protocol'] == 'udp':
            udp_scan(ip)
        else:
            print('Protocol not found')
            sys.exit(0)

    # ip with options without protocol:
    if args['ip'] is not None and args['options'] is not None:
        ip = args['ip']
        getStarted(ip, ports)
        if args['options'] == 'os':
            os_scan(ip)
        elif args['options'] == 'ping':
            ping_scan(ip)
        else:
            options(ip, args['options'])


getArgs()
