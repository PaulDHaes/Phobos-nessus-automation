import os
import argparse
import xml.etree.ElementTree as ET
import time
import subprocess


def run_nmap(ip_list, port, plugin_name):
    # Define the nmap command for each plugin
    commands = {
        "SSH Weak Key Exchange Algorithms Enabled": f"nmap -p{port} --script ssh2-enum-algos {ip_list}",
        "telnet-ntlm-info": f"nmap -p {port} --script telnet-ntlm-info {ip_list}",
        "TLS Version 1.0 Protocol Detection": f"nmap -p {port} --script ssl-enum-ciphers {ip_list}",
        "SSL Version 2 and 3 Protocol Detection": f"nmap -p {port} --script ssl-enum-ciphers {ip_list}",
        "Microsoft Windows SMB Shares Unprivileged Access": f"nmap -p {port} --script smb2-security-mode {ip_list}",
        "Apache Tomcat 8.x < 8.5.78 Spring4Shell (CVE-2022-22965) Mitigations": f"nmap -p {port} --script http-vuln-cve2022-22965 {ip_list}",
        "SSH Weak MAC Algorithms Enabled": f"nmap -p{port} --script ssh2-enum-algos {ip_list}",
        "SSH Server CBC Mode Ciphers Enabled": f"nmap -p{port} --script ssh2-enum-algos {ip_list}",
        "SSL/TLS Diffie-Hellman Modulus <= 1024 Bits (Logjam)": f"nmap -p{port} --script ssl-dh-params {ip_list}",
        "FTP Supports Cleartext Authentication": f"nmap -p{port} --script ftp-anon {ip_list}",
        "SSL Anonymous Cipher Suites Supported": f"nmap -p {port} --script ssl-enum-ciphers {ip_list}",
        "Apache Multiviews Arbitrary Directory Listing": f"nmap -p {port} --script http-apache-negotiation {ip_list}",
        "SSH Weak Algorithms Supported": f"nmap -p {port} --script ssh2-enum-algos {ip_list}",
        "MySQL Protocol Remote User Enumeration": f"nmap -p {port} --script mysql-users {ip_list}",
        "ESXi 6.5 / 6.7 / 7.0 Multiple Vulnerabilities (VMSA-2022-0030)": f"nmap -p {port} -sT -sV -n -A {ip_list}",
        "SSLv3 Padding Oracle On Downgraded Legacy Encryption Vulnerability (POODLE)": f"nmap -p {port} --script ssl-poodle {ip_list}",
    }
    # Get the command for the given plugin, if it exists
    command = commands.get(plugin_name)
    if command:
        return command
    else:
        # non default nmap commands -> need to work on this part as it will automaticly execute
        if plugin_name == "NFS Shares World Readable":
            special_command = f"showmount -e {ip_list} >> {plugin_name.replace(" ", "_")}_{port}_full.txt"
            print("\n" + special_command + "\n")
            time.sleep(1000)
            os.system(special_command)
        elif plugin_name == "SSL Certificate Cannot Be Trusted":
            special_command = f"echo | openssl s_client -servername name -connect {ip_list}:{port} 2>/dev/null | openssl x509 -noout -issuer -subject >> {plugin_name.replace(" ", "_")}_{port}_full.txt"
            print("\n" + special_command + "\n")
            time.sleep(1000)
            os.system(special_command)
        else:
            print(f"No specific nmap command for plugin {plugin_name}.")
        return None


# print the banner
def print_banner():
    print("***********************************************************")
    print(r" _  (`-') (`-').->           <-.(`-')             (`-').-> ")
    print(r" \-.(OO ) (OO )__      .->    __( OO)      .->    ( OO)_   ")
    print(r" _.'    \,--. ,'-'(`-')----. '-'---.\ (`-')----. (_)--\_)  ")
    print(r"(_...--''|  | |  |( OO).-.  '| .-. (/ ( OO).-.  '/    _ /  ")
    print(r"|  |_.' ||  `-'  |( _) | |  || '-' `.)( _) | |  |\_..`--.  ")
    print(r"|  .___.'|  .-.  | \|  |)|  || /`'.  | \|  |)|  |.-._)   \ ")
    print(r"|  |     |  | |  |  '  '-'  '| '--'  /  '  '-'  '\       / ")
    print(r"`--'     `--' `--'   `-----' `------'    `-----'  `-----'  ")
    print("By Paul")
    print("***********************************************************")


# start of main
def main():
    parser = argparse.ArgumentParser(
        prog="phobus.py",
        description="Process .nessus file and run nmap based on findings.",
        epilog="Example: phobus.py -f file.nessus -b",
    )
    parser.add_argument(
        "-f", "--file", help="The .nessus file to process", required=True
    )
    parser.add_argument(
        "-b", "--banner", help="Disables banner (default: True)", action="store_false"
    )
    args = parser.parse_args()

    if args.banner:
        print_banner()

    tree = ET.parse(args.file)
    root = tree.getroot()

    # Mapping of the severity
    severity_mapping = {
        "0": "None",
        "1": "Low",
        "2": "Medium",
        "3": "High",
        "4": "Critical",
    }

    # Collect unique findings for each severity level
    unique_findings = {severity: set() for severity in severity_mapping.values()}
    for block in root:
        if block.tag == "Report":
            for report_host in block:
                for report_item in report_host:
                    severity = report_item.attrib.get("severity")
                    if severity in severity_mapping:
                        plugin_name = report_item.attrib.get("pluginName")
                        ip = report_host.attrib["name"]
                        unique_findings[severity_mapping[severity]].add(
                            (plugin_name, ip)
                        )

    # Print unique findings for each severity level
    for severity, findings in unique_findings.items():
        unique_plugins = set(finding[0] for finding in findings)
        print(f"\n{severity}: {len(unique_plugins)} unique plugin names")
        for plugin in unique_plugins:
            print(f"  - Plugin: {plugin}")

    # Count the number of unique plugin names for each severity level
    print("\nCounts of unique plugin names for each severity level:")
    for severity, findings in unique_findings.items():
        plugin_names = {plugin_name for plugin_name, _ in findings}
        print(f"{severity}: {len(plugin_names)}")

    # Ask the user which severity levels to exclude
    exclude_severities = input("Enter the severity levels to exclude, separated by commas (None, Low, Medium, High, Critical): ")
    exclude_severities = [s.strip().capitalize() for s in exclude_severities.split(",")]

    print("Excluded Severity Levels:", exclude_severities)

    # Group findings by plugin name and port
    findings_by_plugin = {}
    for block in root:
        if block.tag == "Report":
            for report_host in block:
                for report_item in report_host:
                    severity = report_item.attrib.get("severity")
                    if severity:  # Check if severity attribute exists
                        severity = severity_mapping.get(
                            severity
                        )  # Map severity to capitalized value
                        if (
                            severity not in exclude_severities
                        ):  # Check if severity level should be excluded
                            plugin_name = report_item.attrib.get("pluginName")
                            ip = report_host.attrib["name"]
                            port = report_item.attrib["port"]
                            key = (plugin_name, severity)
                            if key not in findings_by_plugin:
                                findings_by_plugin[key] = []
                            findings_by_plugin[key].append((port, ip))

    # Initialize vars
    unique_commands = {}
    executed_commands = set()
    unsupported_plugins = set()
    same_plugin_other_port = ""

    for (plugin_name, severity), ips in sorted(findings_by_plugin.items(), key=lambda x: (x[1][0][0], x[0][0])):
        count = 1
        if (plugin_name, port) in unique_commands:
            print("Skipping duplicate entry:", (plugin_name, port))
            continue
        # Group IPs by port
        ips_by_port = {}
        for port, ip in ips:
            if port not in ips_by_port:
                ips_by_port[port] = []
            ips_by_port[port].append(ip)

        for port, ip_list in ips_by_port.items():
            # Check if the plugin is already marked as unsupported
            if plugin_name in unsupported_plugins:
                continue
            command = run_nmap(",".join(ip_list), port, plugin_name)  # Join IPs with comma
            if command:
                print(f"{count}. Found script to use with this finding {plugin_name} and severity ({severity})")
                if same_plugin_other_port == plugin_name:
                    user_input = "all"
                else:
                    user_input = input(f"Do you want to run the command for '{plugin_name}' on port ({port}) (yes/no/all): ").lower()
                    output_type_input = input("How do you want to output 1 big output file/1 output file for each diffrent plugin name (single/multiple): ").lower()
                    if output_type_input =="single":
                        output_type=" >> single.txt"
                    elif output_type_input =="multiple":
                        output_type=f" >> {plugin_name.replace(' ', '_')}_multiple.txt"
                #os.system(f"echo '\n' {output_type_input}")
                time.sleep(1)
                if user_input == "yes":
                    cmd = f"{command} {output_type}"
                    unique_commands[(plugin_name, port)] = cmd
                    print("\n" + cmd + "\n")
                    subprocess.run(cmd, shell=True)
                    executed_commands.add((plugin_name, port))
                elif user_input == "all":
                    same_plugin_other_port = plugin_name
                    cmd = f"{command} {output_type}"
                    unique_commands[(plugin_name, port)] = cmd
                    print("\n" + cmd + "\n")
                    subprocess.run(cmd, shell=True)
                    executed_commands.add((plugin_name, port))
                    #break
                elif user_input == "no":
                    print(f"Not running '{command}' for {plugin_name} ({severity})")
                    count += 1
                    # Continue to the next port
                else:
                    print(f"Invalid option: {user_input}")
                    count += 1
            else:
                # Mark the plugin as unsupported if no command is found
                unsupported_plugins.add(plugin_name)

if __name__ == "__main__":
    main()
