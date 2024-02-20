# python-nmap must be installed with pip and nmap, vulners must be installed + on PATH

# Import nmap module
try:
    import nmap
except ModuleNotFoundError:
    print("Error: python-nmap module not found.")
    input("Press Enter to continue...")
    exit()

# Ensure nmap is added to PATH
def initialize_nmap():
    try:
        return nmap.PortScanner()
    except nmap.nmap.PortScannerError:
        print("Error: Nmap must be installed and added to PATH.")
        input("Press Enter to continue...")
        exit()

# Scan a given host with vulners script
def scan_ip(nmScan, address):
    print("Gathering information. This may take some time...\n")
    nmScan.scan(address, arguments = "--script vulners -sV")

    # If nothing shows up (could be for multiple reasons)
    if not nmScan.all_hosts():
        print("Error: No information found. Please ensure proper input, ensure vulners script is installed, and try again.")
        print("It is also possible that all ports are closed.")
        input("Press Enter to continue...\n")
        exit()

# Display vulnerabilities by combing through JSON
def show_vulnerabilities(nmScan):
    for host in nmScan.all_hosts():
        print('Scanning {0} ({1})'.format(host, nmScan[host].hostname()))
        print('Host status: {0}'.format(nmScan[host].state()))

        for protocol in nmScan[host].all_protocols():
            print('\n-------- {0} Protocol --------'.format(protocol.upper()))

            open_ports = nmScan[host][protocol].keys()
            sorted(open_ports)

            for port in open_ports:
                print ('\n-> Open port: {0}'.format(port))

                # If no vulnerabilities, 'script' may be missing from JSON
                if 'script' in nmScan[host][protocol][port]:

                    # Depending on the scan, 'vulners' may be missing from JSON
                    if 'vulners' in nmScan[host][protocol][port]['script']:
                        print('    Vulnerabilities:')
                        vulns = nmScan[host][protocol][port]['script']['vulners'].split('\n')

                        for vuln in vulns:
                            if vuln != '':
                                vuln_parts = vuln.strip().split('\t')

                                # Print CVE's
                                if len(vuln_parts) == 3:
                                    cve, score, link = vuln_parts
                                    print('    - Identifier: {0}, Score: {1} Link: {2}'.format(cve, score, link))

# Main function
def main():
    nmScan = initialize_nmap()
    address = input("Enter the IP/domain to scan: ").replace(" ", "")

    scan_ip(nmScan, address)
    show_vulnerabilities(nmScan)

    input("\nPress Enter to continue...")

# Call main only if directly from Python interpreter
if __name__ == "__main__":
    main()