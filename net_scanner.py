import scapy.all as scapy
import optparse

parser = optparse.OptionParser()
parser.add_option("-r", dest="ip", help="Specify an IP or an IP Range")
(options, arg) = parser.parse_args()


def scan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        clients_list.append(clients_dict)
    return clients_list


def print_result(final_result):
    print("IP Address\t\t\tMAC Address\n---------------------------------------------------")
    for client in final_result:
        print(client["ip"] + "\t\t\t" + client["mac"])


scan_result = scan(options.ip)
print_result(scan_result)

