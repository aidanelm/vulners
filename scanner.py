# Author: Aidan Elm | 2024-08-02

""" Install nmap module via pip as python-nmap. """

import sys # Exit

# Import nmap module
try:
    import nmap
except ModuleNotFoundError:
    print('Error: python-nmap module and/or nmap not found.')
    input('Press Enter to continue...')
    sys.exit()

# Ensure nmap is added to PATH
def initialize_nmap() -> nmap.PortScanner:

    """
    Inputs: None
    Outputs: PortScanner object
    """

    try:
        return nmap.PortScanner()
    except nmap.nmap.PortScannerError:
        print('Error: Nmap must be installed and added to PATH.')
        input('Press Enter to continue...')
        sys.exit()

# Scan a given host with vulners script
def scan_ip(nmap_scanner: nmap.PortScanner, address: str) -> None:

    """
    Inputs: PortScanner object, IP address
    Outputs: None (modifies PortScanner object)
    """

    print('Gathering information. This may take some time...\n')
    nmap_scanner.scan(address, arguments = '--script vulners -sV')

    # If nothing shows up (could be for multiple reasons)
    if not nmap_scanner.all_hosts():
        print('Error: No information found.')
        print('Please ensure proper input and ensure vulners script is installed.')
        print('It is also possible that all ports are closed.')
        input('Press Enter to continue...\n')
        sys.exit()

# Display vulnerabilities by combing through JSON
def show_vulnerabilities(nmap_scanner: nmap.PortScanner):

    """
    Inputs: PortScanner object
    Outputs: None (prints information)
    """

    for host in nmap_scanner.all_hosts():
        print(f'Scanning {host} ({nmap_scanner[host].hostname()})')
        print(f'Host status: {nmap_scanner[host].state()}')

        for protocol in nmap_scanner[host].all_protocols():
            print(f'\n-------- {protocol.upper()} Protocol --------')

            open_ports = nmap_scanner[host][protocol].keys()
            sorted(open_ports)

            for port in open_ports:
                print (f'\n-> Open port: {port}')

                # If no vulnerabilities, 'script' may be missing from JSON
                if 'script' in nmap_scanner[host][protocol][port]:

                    # Depending on the scan, 'vulners' may be missing from JSON
                    if 'vulners' in nmap_scanner[host][protocol][port]['script']:
                        print('    Vulnerabilities:')
                        vulns = nmap_scanner[host][protocol][port]['script']['vulners'].split('\n')

                        for vuln in vulns:
                            if vuln != '':
                                vuln_parts = vuln.strip().split('\t')

                                # Print CVE's
                                if len(vuln_parts) == 3:
                                    cve, score, link = vuln_parts
                                    print(f'    - Identifier: {cve}, Score: {score} Link: {link}')

if __name__ == '__main__':

    try:
        scanner = initialize_nmap()
        selected_address = input('Enter the IP/domain to scan: ').replace(' ', '')

        scan_ip(scanner, selected_address)
        show_vulnerabilities(scanner)

        input('\nPress Enter to continue...')

    except KeyboardInterrupt:
        print('\nScan interrupted by user.')
