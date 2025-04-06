import paramiko
import time
import threading
import logging
from colorama import Fore, Back, Style

VULN_MITIGATIONS = {
    'Benign': 'No mitigation required.',
    'Botnet': 'Stopping suspicious processes and blocking IP ranges.',
    'Bruteforce': 'Implementing account lockout, changing passwords, and disabling brute force login.',
    'DoS': 'Blocking the attack traffic, increasing server resources, and rate-limiting connections.',
    'DDoS': 'Use firewall to block the attack traffic and activate DDoS protection services.',
    'Infiltration': 'Check for unauthorized access, change passwords, and increase security layers.',
    'Portscan': 'Block suspicious IPs and implement intrusion detection systems.',
    'Webattack': 'Apply security patches, and firewall protections, and restrict HTTP methods.'
}

# Configure logging
logging.basicConfig(filename='mitigation.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ssh_connect(host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        logging.info(f"Successfully connected to {host}")
        return client
    except Exception as e:
        logging.error(f"Error connecting to {host}: {e}")
        return None

def run_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        return output, error
    except Exception as e:
        logging.error(f"Error executing command: {command}, {e}")
        return None, str(e)

def mitigate_botnet(client):
    commands = [
        "pkill -f botnet",
        "iptables -A INPUT -s <attacker-ip> -j DROP"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Botnet Mitigation: {output if output else error}")
        logging.info(f"Botnet Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_bruteforce(client):
    commands = [
        "echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=900' >> /etc/pam.d/common-auth",
        "service ssh restart"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Bruteforce Mitigation: {output if output else error}")
        logging.info(f"Bruteforce Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_dos(client):
    commands = [
        "iptables -A INPUT -p tcp --syn --dport 80 -m limit --limit 1/s -j ACCEPT",
        "sysctl -w net.ipv4.tcp_syncookies=1"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"DoS Mitigation: {output if output else error}")
        logging.info(f"DoS Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_ddos(client):
    commands = [
        "iptables -A INPUT -p tcp --dport 80 -j DROP",
        "service nginx restart",
        "ufw enable"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"DDoS Mitigation: {output if output else error}")
        logging.info(f"DDoS Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_infiltration(client):
    commands = [
        "passwd root",
        "chmod 700 /etc/shadow",
        "ufw allow from <trusted-ip> to any port 22"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Infiltration Mitigation: {output if output else error}")
        logging.info(f"Infiltration Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_portscan(client):
    commands = [
        "iptables -A INPUT -s <attacker-ip> -j DROP",
        "ufw enable"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Portscan Mitigation: {output if output else error}")
        logging.info(f"Portscan Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_webattack(client):
    commands = [
        "apt-get update && apt-get upgrade -y",
        "ufw allow from <trusted-ip> to any port 80",
        "service apache2 restart"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Webattack Mitigation: {output if output else error}")
        logging.info(f"Webattack Mitigation: {output if output else error}")
        time.sleep(2)

def handle_vulnerability(vuln, client):
    mitigation_strategy = VULN_MITIGATIONS.get(vuln, 'No mitigation available.')
    print(f"{Fore.YELLOW}Vulnerability detected: {vuln}")
    print(f"{Fore.GREEN}Applying mitigation: {mitigation_strategy}{Style.RESET_ALL}")
    
    if vuln == 'Botnet':
        mitigate_botnet(client)
    elif vuln == 'Bruteforce':
        mitigate_bruteforce(client)
    elif vuln == 'DoS':
        mitigate_dos(client)
    elif vuln == 'DDoS':
        mitigate_ddos(client)
    elif vuln == 'Infiltration':
        mitigate_infiltration(client)
    elif vuln == 'Portscan':
        mitigate_portscan(client)
    elif vuln == 'Webattack':
        mitigate_webattack(client)
    else:
        logging.warning("Unknown vulnerability type.")
        print(f"{Fore.RED}Unknown vulnerability type.{Style.RESET_ALL}")

def process_vulnerabilities(vulns, client):
    for vuln in vulns:
        handle_vulnerability(vuln, client)

def main():
    host = input("Enter the VM IP address: ")
    username = input("Enter the SSH username: ")
    password = input("Enter the SSH password: ")
    
    client = ssh_connect(host, username, password)
    
    if client:
        print(f"{Fore.CYAN}Connected to {host} successfully!{Style.RESET_ALL}")
        while True:
            print("\nSelect the vulnerability to mitigate:")
            print("1. Botnet")
            print("2. Bruteforce")
            print("3. DoS")
            print("4. DDoS")
            print("5. Infiltration")
            print("6. Portscan")
            print("7. Webattack")
            print("8. Batch Mitigation (Multiple Vulnerabilities)")
            print("9. Exit")
            
            choice = input("Enter your choice: ")
            if choice == '1':
                handle_vulnerability('Botnet', client)
            elif choice == '2':
                handle_vulnerability('Bruteforce', client)
            elif choice == '3':
                handle_vulnerability('DoS', client)
            elif choice == '4':
                handle_vulnerability('DDoS', client)
            elif choice == '5':
                handle_vulnerability('Infiltration', client)
            elif choice == '6':
                handle_vulnerability('Portscan', client)
            elif choice == '7':
                handle_vulnerability('Webattack', client)
            elif choice == '8':
                vulns = input("Enter the vulnerabilities to mitigate (comma separated, e.g., Botnet,DoS): ").split(',')
                process_vulnerabilities([v.strip() for v in vulns], client)
            elif choice == '9':
                print(f"{Fore.RED}Exiting the program.{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        
        client.close()
    else:
        print(f"{Fore.RED}Failed to connect to the VM. Please check the credentials and try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()

import paramiko
import time
import threading
import logging
from colorama import Fore, Back, Style

VULN_MITIGATIONS = {
    'Benign': 'No mitigation required.',
    'Botnet': 'Stopping suspicious processes and blocking IP ranges.',
    'Bruteforce': 'Implementing account lockout, changing passwords, and disabling brute force login.',
    'DoS': 'Blocking the attack traffic, increasing server resources, and rate-limiting connections.',
    'DDoS': 'Use firewall to block the attack traffic and activate DDoS protection services.',
    'Infiltration': 'Check for unauthorized access, change passwords, and increase security layers.',
    'Portscan': 'Block suspicious IPs and implement intrusion detection systems.',
    'Webattack': 'Apply security patches, and firewall protections, and restrict HTTP methods.'
}

# Configure logging
logging.basicConfig(filename='mitigation.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def ssh_connect(host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        logging.info(f"Successfully connected to {host}")
        return client
    except Exception as e:
        logging.error(f"Error connecting to {host}: {e}")
        return None

def run_command(client, command):
    try:
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        return output, error
    except Exception as e:
        logging.error(f"Error executing command: {command}, {e}")
        return None, str(e)

def mitigate_botnet(client):
    commands = [
        "pkill -f botnet",
        "iptables -A INPUT -s <attacker-ip> -j DROP"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Botnet Mitigation: {output if output else error}")
        logging.info(f"Botnet Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_bruteforce(client):
    commands = [
        "echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=900' >> /etc/pam.d/common-auth",
        "service ssh restart"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Bruteforce Mitigation: {output if output else error}")
        logging.info(f"Bruteforce Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_dos(client):
    commands = [
        "iptables -A INPUT -p tcp --syn --dport 80 -m limit --limit 1/s -j ACCEPT",
        "sysctl -w net.ipv4.tcp_syncookies=1"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"DoS Mitigation: {output if output else error}")
        logging.info(f"DoS Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_ddos(client):
    commands = [
        "iptables -A INPUT -p tcp --dport 80 -j DROP",
        "service nginx restart",
        "ufw enable"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"DDoS Mitigation: {output if output else error}")
        logging.info(f"DDoS Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_infiltration(client):
    commands = [
        "passwd root",
        "chmod 700 /etc/shadow",
        "ufw allow from <trusted-ip> to any port 22"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Infiltration Mitigation: {output if output else error}")
        logging.info(f"Infiltration Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_portscan(client):
    commands = [
        "iptables -A INPUT -s <attacker-ip> -j DROP",
        "ufw enable"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Portscan Mitigation: {output if output else error}")
        logging.info(f"Portscan Mitigation: {output if output else error}")
        time.sleep(2)

def mitigate_webattack(client):
    commands = [
        "apt-get update && apt-get upgrade -y",
        "ufw allow from <trusted-ip> to any port 80",
        "service apache2 restart"
    ]
    for command in commands:
        output, error = run_command(client, command)
        print(f"Webattack Mitigation: {output if output else error}")
        logging.info(f"Webattack Mitigation: {output if output else error}")
        time.sleep(2)

def handle_vulnerability(vuln, client):
    mitigation_strategy = VULN_MITIGATIONS.get(vuln, 'No mitigation available.')
    print(f"{Fore.YELLOW}Vulnerability detected: {vuln}")
    print(f"{Fore.GREEN}Applying mitigation: {mitigation_strategy}{Style.RESET_ALL}")
    
    if vuln == 'Botnet':
        mitigate_botnet(client)
    elif vuln == 'Bruteforce':
        mitigate_bruteforce(client)
    elif vuln == 'DoS':
        mitigate_dos(client)
    elif vuln == 'DDoS':
        mitigate_ddos(client)
    elif vuln == 'Infiltration':
        mitigate_infiltration(client)
    elif vuln == 'Portscan':
        mitigate_portscan(client)
    elif vuln == 'Webattack':
        mitigate_webattack(client)
    else:
        logging.warning("Unknown vulnerability type.")
        print(f"{Fore.RED}Unknown vulnerability type.{Style.RESET_ALL}")

def process_vulnerabilities(vulns, client):
    for vuln in vulns:
        handle_vulnerability(vuln, client)

def main():
    host = input("Enter the VM IP address: ")
    username = input("Enter the SSH username: ")
    password = input("Enter the SSH password: ")
    
    client = ssh_connect(host, username, password)
    
    if client:
        print(f"{Fore.CYAN}Connected to {host} successfully!{Style.RESET_ALL}")
        while True:
            print("\nSelect the vulnerability to mitigate:")
            print("1. Botnet")
            print("2. Bruteforce")
            print("3. DoS")
            print("4. DDoS")
            print("5. Infiltration")
            print("6. Portscan")
            print("7. Webattack")
            print("8. Batch Mitigation (Multiple Vulnerabilities)")
            print("9. Exit")
            
            choice = input("Enter your choice: ")
            if choice == '1':
                handle_vulnerability('Botnet', client)
            elif choice == '2':
                handle_vulnerability('Bruteforce', client)
            elif choice == '3':
                handle_vulnerability('DoS', client)
            elif choice == '4':
                handle_vulnerability('DDoS', client)
            elif choice == '5':
                handle_vulnerability('Infiltration', client)
            elif choice == '6':
                handle_vulnerability('Portscan', client)
            elif choice == '7':
                handle_vulnerability('Webattack', client)
            elif choice == '8':
                vulns = input("Enter the vulnerabilities to mitigate (comma separated, e.g., Botnet,DoS): ").split(',')
                process_vulnerabilities([v.strip() for v in vulns], client)
            elif choice == '9':
                print(f"{Fore.RED}Exiting the program.{Style.RESET_ALL}")
                break
            else:
                print(f"{Fore.RED}Invalid choice! Please try again.{Style.RESET_ALL}")
        
        client.close()
    else:
        print(f"{Fore.RED}Failed to connect to the VM. Please check the credentials and try again.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()
