import nmap

def get_device_info(ip):
    # Create a new instance of the nmap scanner
    mynmap = nmap.PortScanner()

    # Inform the user that the scan may take some time
    print("\nThis may take a couple of minutes...\n")

    # Perform a detailed scan of the specified IP address
    scan = mynmap.scan(ip, '1-1024', '-v -sS -sV -O -A -e ens3')

    # Parse and print relevant information from the scan result
    print("\n= = = = = = = HOST {} = = = = = = =".format(ip))

    print("\n\nGENERAL INFO")

    # Extract MAC address if available
    mac = scan['scan'][ip]['addresses'].get('mac', None)
    if mac:
        print("\n-> MAC address: {}".format(mac))

    # Extract operating system information
    os = scan['scan'][ip]['osmatch'][0]['name']
    print("-> Operating system: {}".format(os))

    # Extract device uptime information
    uptime = scan['scan'][ip]['uptime']['lastboot']
    print("-> Device uptime: {}".format(uptime))

    # Print port states
    print("\n\nPORTS\n")

    for port, data in scan['scan'][ip]['tcp'].items():
        print("-> {} | {} | {}".format(port, data['name'], data['state']))

    print("\n\nOTHER INFO\n")

    # Print the NMAP command used for scanning
    print("-> NMAP command: {}".format(scan['nmap']['command_line']))

    # Extract and print NMAP version
    version = ".".join(map(str, mynmap.nmap_version()[:2]))
    print("-> NMAP version: {}".format(version))

    # Print the time elapsed during the scan
    print("-> Time elapsed: {} seconds".format(scan['nmap']['scanstats']['elapsed']))

    # Print the timestamp of the scan
    print("-> Time of scan: {}".format(scan['nmap']['scanstats']['timestr']))
    print("\n\n")

def scan_network():
    # Create a new instance of the nmap scanner
    mynmap = nmap.PortScanner()

    # Inform the user that the scan may take some time
    print("\nThis may take a couple of minutes...\n")

    # Scan the network for open ports on specified devices
    scan = mynmap.scan(ports='1-1024', arguments='-sS -e ens3 -iL /home/osboxes/Apps/ip.txt')

    for device in scan['scan']:
        print("\nPorts open on {}:".format(device))
        for port, data in scan['scan'][device]['tcp'].items():
            if data['state'] == 'open':
                print("--> {} | {}".format(port, data['name']))

if __name__ == "__main__":
    while True:
        # User menu
        print("""\nWhat do you want to do?\n
                    1 - Get detailed info about a device
                    2 - Scan the network for open ports
                    e - Exit the application""")

        # Get user input
        user_input = input("\nEnter your option: ")

        # Handling user options
        if user_input == "1":
            # Ask the user for the IP address to scan
            ip = input("\nPlease enter the IP address to scan: ")
            # Call the function to get detailed information about the device
            get_device_info(ip)
        elif user_input == "2":
            # Call the function to scan the network for open ports
            scan_network()
        elif user_input == "e":
            # Inform the user and exit the program
            print('\nExiting program...\n')
            break
        else:
            # Inform the user of invalid input and continue to the next iteration
            print("\nInvalid input. Try again!\n")
            
# End of Program