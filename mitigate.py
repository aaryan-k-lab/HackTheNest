import paramiko
import time

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

def ssh_connect(host, username, password):
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(host, username=username, password=password)
        return client
    except Exception as e:
        print(f"Error connecting to {host}: {e}")
        return None

def mitigate_botnet(client):
    commands = [
        "pkill -f botnet",
        "iptables -A INPUT -s <attacker-ip> -j DROP"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_bruteforce(client):
    commands = [
        "echo 'auth required pam_tally2.so deny=5 onerr=fail unlock_time=900' >> /etc/pam.d/common-auth",
        "service ssh restart"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_dos(client):
    commands = [
        "iptables -A INPUT -p tcp --syn --dport 80 -m limit --limit 1/s -j ACCEPT",
        "sysctl -w net.ipv4.tcp_syncookies=1"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_ddos(client):
    commands = [
        "iptables -A INPUT -p tcp --dport 80 -j DROP",
        "service nginx restart",
        "ufw enable"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_infiltration(client):
    commands = [
        "passwd root",
        "chmod 700 /etc/shadow",
        "ufw allow from <trusted-ip> to any port 22"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_portscan(client):
    commands = [
        "iptables -A INPUT -s <attacker-ip> -j DROP",
        "ufw enable"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def mitigate_webattack(client):
    commands = [
        "apt-get update && apt-get upgrade -y",
        "ufw allow from <trusted-ip> to any port 80",
        "service apache2 restart"
    ]
    for command in commands:
        stdin, stdout, stderr = client.exec_command(command)
        print(stdout.read().decode())
        print(stderr.read().decode())
        time.sleep(2)

def handle_vulnerability(vuln, client):
    mitigation_strategy = VULN_MITIGATIONS.get(vuln, 'No mitigation available.')
    print(f"Vulnerability detected: {vuln}")
    print(f"Applying mitigation: {mitigation_strategy}")
    
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
        print("Unknown vulnerability type.")

def main():
    host = input("Enter the VM IP address: ")
    username = input("Enter the SSH username: ")
    password = input("Enter the SSH password: ")
    vuln = input("Enter the vulnerability type (e.g., Botnet, Bruteforce, DoS, DDoS, Infiltration, Portscan, Webattack): ")

    client = ssh_connect(host, username, password)
    
    if client:
        handle_vulnerability(vuln, client)
        client.close()
    else:
        print("Failed to connect to the VM.")

if __name__ == "__main__":
    main()
