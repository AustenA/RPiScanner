import sys
import os
#Some network tools to get the subnet mask and stuff
from netaddr import *
#This allows the program to calculate the number of IPs on the network.
from ipaddress import ip_network
#Splices arrays
from itertools import islice
#these speed up the scanning process by allowing multithreading. Using more CPU to do more at once. And allows for timing out things that take too long.
from multiprocessing import Manager, Process
from multiprocessing.pool import ThreadPool
#This is a tool that uses arp and ping to get the mac address from a device on the network.
from getmac import get_mac_address
#Mac Vender Lookup
from manuf import manuf
p = manuf.MacParser(update=False)
#Parsing of command line input
import argparse
###Paramiko for sshing
import paramiko
ssh=paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

parser = argparse.ArgumentParser()
parser.add_argument("-t", "--timeout", help="Timeout Of Scanner", default="25", type=int)
parser.add_argument("-i", "--ipaddr", help="IP Address", default="")
parser.add_argument("-c", "--ipcidr", help="Network CIDR", default="")
parser.add_argument("-m", "--max", help="Max Addresses", default="1000")
parser.add_argument("-f", "--file", help="Output File For Addresses", default="")
parser.add_argument("-k", "--hack", help="Attempt to SSH into Pi's",action="store_true")
parser.add_argument("-s", "--ssh", help="Configure an SSH port",default="22")
parser.add_argument("-u", "--user", help="Set a username for SSH",default="pi")
parser.add_argument("-p", "--password", help="Set a password for SSH",default="raspberry")
parser.add_argument("-q", "--quiet", help="Suppress most output",action="store_true")
args = parser.parse_args()

TIMEOUT = args.timeout
MAX_ADDRESSES = int(args.max)
PROCESS_LIMIT = 48

#These 2 functions go hand and hand. The get_mac is what actually retrieves it. The second allows us to make it threaded and with a timeout.
def get_mac(ip_address: str, addresses: dict) -> None:
    #Get a mac address for the provided IP and store it.
    mac_address = get_mac_address(ip=ip_address)
    if mac_address:
        man = p.get_manuf(mac_address)
        if not args.quiet:
            print(f"{ip_address} -> {mac_address} - {man}")
        addresses[ip_address] = mac_address, man

def try_get_mac(args: tuple) -> None:
    #This is what's being timed out. This is why the entire code is so complex mainly. Process is a pain in the butt.
    process = Process(target=get_mac, args=args)
    process.daemon = True
    process.start()
    process.join(TIMEOUT)
    process.terminate()

def connect(hackIP):
    #This is the line that connects to the pi
    try:
        ssh.connect(str(hackIP),username=args.user,password=args.password, timeout = 3, port=int(args.ssh))
        return True
    except:
        return False
        pass

def main() -> None:
    if not args.ipaddr:
        try:
            IpConfig = os.popen("ipconfig").read()
            for item in IpConfig.split("\n"):
                if "Default" in item:
                    myIp = item.strip().split(":")[1].strip(" ")
        except:
            print("Failed To Get IP Information Please Set Manually")
            exit(1)
    else:
        myIp = args.ipaddr

    if not args.ipcidr:
        for item in IpConfig.split("\n"):
            if "Subnet Mask" in item:
                myMask = item.strip().split(":")[1].strip(" ")
                myCIDR = str(IPAddress(myMask).netmask_bits())
    else:
        myCIDR = args.ipcidr
        
    ip = '{}/{}'.format(myIp, myCIDR)
        

    # Get MAC addresses for every device in the network.
    manager = Manager()
    mac_addresses: dict = manager.dict()
    # Scan first MAX_ADDRESSES addresses in network range from scan
    addresses = islice(ip_network(str(ip),False), MAX_ADDRESSES)

    with ThreadPool(processes=PROCESS_LIMIT) as pool:
        pool.map(try_get_mac, ((address, mac_addresses) for address in addresses))

    #Export IPs to File
    if args.file:
        fname = args.file
        f = open(fname,"a+") 
        for i in mac_addresses.items():
            f.write(f"{i[0]} -> {i[1][0]} - {i[1][1]}")
            if args.hack:
                if i[1][1] == "Raspberr":
                    if connect(i[0]):
                        f.write(" - Success")
                        if not args.quiet:
                            print(f"{i[0]} - Connected With Default Credentials")
                        ssh.close()
                    else:
                        f.write(" - Failed")
                        if not args.quiet:
                            print(f"{i[0]} - Could Not Connect")
            f.write("\n")
        f.close()

    if (not args.file) and args.hack:
        for i in mac_addresses.items():
            if i[1][1] == "Raspberr":
                if connect(i[0]):
                    if not args.quiet:
                        print(f"{i[0]} - Connected With Default Credentials")
                    ssh.close()
                else:
                    if not args.quiet:
                        print(f"{i[0]} - Could Not Connect")
        #Get item by key
        #listOfKeys = list()
        #listOfItems = mac_addresses.items()
        #for item in listOfItems:
        #    if item[1][1] == "MurataMa":
        #        listOfKeys.append(item[0])
        #print(listOfKeys)

if __name__ == "__main__":
    main()