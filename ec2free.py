#!/usr/bin/env python3
import boto3
import os
import time
import sys
from botocore.exceptions import ClientError

AWS_PROFILE = "default"

def get_account_info(session):
    """Display account information for verification"""
    try:
        sts = session.client('sts')
        identity = sts.get_caller_identity()
        
        print("=" * 60)
        print("AWS ACCOUNT INFORMATION")
        print("=" * 60)
        print(f"Account ID: {identity.get('Account', 'Unknown')}")
        print(f"User/Role: {identity.get('Arn', 'Unknown')}")
        
        # Try to get account email
        try:
            account_client = session.client('account')
            contact_info = account_client.get_contact_information()
            if 'ContactInformation' in contact_info:
                email = contact_info['ContactInformation'].get('EmailAddress', 'Not available')
                print(f"Account Email: {email}")
        except Exception:
            try:
                account_client = session.client('account')
                alternate_contact = account_client.get_alternate_contact(AlternateContactType='BILLING')
                if 'AlternateContact' in alternate_contact:
                    email = alternate_contact['AlternateContact'].get('EmailAddress', 'Not available')
                    print(f"Billing Email: {email}")
            except Exception:
                print("Account Email: Unable to retrieve")
        
        print("=" * 60)
        
    except Exception as e:
        print(f"Error getting account info: {str(e)}")

def get_available_regions(session):
    """Get list of available regions"""
    try:
        ec2 = session.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions()
        regions = [region['RegionName'] for region in response['Regions']]
        return sorted(regions)
    except Exception as e:
        print(f"Error getting regions: {str(e)}")
        return ['us-east-1', 'us-west-2', 'eu-west-1']

def select_region(session):
    """Allow user to select AWS region"""
    regions = get_available_regions(session)
    
    print("\nAvailable AWS Regions:")
    print("-" * 30)
    for i, region in enumerate(regions, 1):
        print(f"{i:2}. {region}")
    
    while True:
        try:
            choice = input(f"\nSelect region (1-{len(regions)}) [default: 1 for {regions[0]}]: ").strip()
            if not choice:
                return regions[0]
            
            index = int(choice) - 1
            if 0 <= index < len(regions):
                return regions[index]
            else:
                print(f"Please enter a number between 1 and {len(regions)}")
        except ValueError:
            print("Please enter a valid number")

def get_local_ssh_keys():
    """Find SSH keys in the user's .ssh directory"""
    ssh_dir = os.path.expanduser("~/.ssh")
    ssh_keys = []
    
    if os.path.exists(ssh_dir):
        for file in os.listdir(ssh_dir):
            if file.endswith('.pub'):
                key_path = os.path.join(ssh_dir, file)
                # Get the private key name (without .pub)
                private_key = file[:-4]
                private_key_path = os.path.join(ssh_dir, private_key)
                
                if os.path.exists(private_key_path):
                    ssh_keys.append({
                        'name': private_key,
                        'public_key_path': key_path,
                        'private_key_path': private_key_path
                    })
    
    return ssh_keys

def select_ssh_key():
    """Allow user to select SSH key"""
    ssh_keys = get_local_ssh_keys()
    
    if not ssh_keys:
        print("\n⚠️  No SSH key pairs found in ~/.ssh/")
        print("Please generate SSH keys first:")
        print("ssh-keygen -t rsa -b 4096 -f ~/.ssh/pentest_key")
        sys.exit(1)
    
    print("\nAvailable SSH Keys:")
    print("-" * 30)
    for i, key in enumerate(ssh_keys, 1):
        print(f"{i}. {key['name']}")
    
    while True:
        try:
            choice = input(f"\nSelect SSH key (1-{len(ssh_keys)}) [default: 1]: ").strip()
            if not choice:
                return ssh_keys[0]
            
            index = int(choice) - 1
            if 0 <= index < len(ssh_keys):
                return ssh_keys[index]
            else:
                print(f"Please enter a number between 1 and {len(ssh_keys)}")
        except ValueError:
            print("Please enter a valid number")

def get_ubuntu_ami(ec2_client, region):
    """Get the latest Ubuntu 24.04 LTS AMI ID"""
    try:
        # Ubuntu 24.04 LTS AMI filter
        response = ec2_client.describe_images(
            Filters=[
                {'Name': 'name', 'Values': ['ubuntu/images/hvm-ssd/ubuntu-noble-24.04-amd64-server-*']},
                {'Name': 'owner-id', 'Values': ['099720109477']},  # Canonical
                {'Name': 'state', 'Values': ['available']},
                {'Name': 'architecture', 'Values': ['x86_64']},
                {'Name': 'virtualization-type', 'Values': ['hvm']},
                {'Name': 'root-device-type', 'Values': ['ebs']}
            ],
            Owners=['099720109477']
        )
        
        if not response['Images']:
            print(f"⚠️  No Ubuntu 24.04 AMI found in {region}")
            return None
        
        # Sort by creation date and get the latest
        latest_ami = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)[0]
        
        print(f"✅ Found Ubuntu AMI: {latest_ami['ImageId']} ({latest_ami['Name']})")
        return latest_ami['ImageId']
        
    except Exception as e:
        print(f"Error finding Ubuntu AMI: {str(e)}")
        return None

def create_key_pair(ec2_client, key_name, public_key_content):
    """Create AWS key pair from local public key"""
    try:
        # Check if key pair already exists
        try:
            response = ec2_client.describe_key_pairs(KeyNames=[key_name])
            print(f"✅ Key pair '{key_name}' already exists in AWS")
            return key_name
        except ClientError as e:
            if e.response['Error']['Code'] != 'InvalidKeyPair.NotFound':
                raise
        
        # Create new key pair
        print(f"Creating key pair '{key_name}' in AWS...")
        ec2_client.import_key_pair(
            KeyName=key_name,
            PublicKeyMaterial=public_key_content
        )
        print(f"✅ Key pair '{key_name}' created successfully")
        return key_name
        
    except Exception as e:
        print(f"Error creating key pair: {str(e)}")
        return None

def create_security_group(ec2_client, region):
    """Create security group with SSH and HTTP access"""
    sg_name = f"pentest-sg-{int(time.time())}"
    
    try:
        print("Creating security group...")
        response = ec2_client.create_security_group(
            GroupName=sg_name,
            Description="Pentesting security group - SSH and HTTP access"
        )
        
        sg_id = response['GroupId']
        print(f"✅ Security group created: {sg_id}")
        
        # Add SSH rule (port 22)
        ec2_client.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'SSH access from anywhere'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 80,
                    'ToPort': 80,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTP access from anywhere'}]
                },
                {
                    'IpProtocol': 'tcp',
                    'FromPort': 443,
                    'ToPort': 443,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0', 'Description': 'HTTPS access from anywhere'}]
                }
            ]
        )
        
        print("✅ Security group rules added (SSH, HTTP, HTTPS)")
        return sg_id
        
    except Exception as e:
        print(f"Error creating security group: {str(e)}")
        return None

def check_all_regions_for_instances(session):
    """Check all AWS regions for existing pentest instances"""
    print("\n🌍 Scanning ALL AWS regions for existing pentest instances...")
    print("This may take a moment...")
    
    all_instances = []
    
    try:
        # Get all available regions
        ec2_global = session.client('ec2', region_name='us-east-1')
        regions_response = ec2_global.describe_regions()
        all_regions = [region['RegionName'] for region in regions_response['Regions']]
        
        print(f"Checking {len(all_regions)} regions...")
        
        for region in all_regions:
            try:
                print(f"  📍 Checking {region}...", end='')
                ec2_client = session.client('ec2', region_name=region)
                
                # Look for instances with pentest tags
                response = ec2_client.describe_instances(
                    Filters=[
                        {'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopping', 'stopped']},
                        {'Name': 'tag:Purpose', 'Values': ['Pentesting']}
                    ]
                )
                
                region_instances = []
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        if instance['State']['Name'] != 'terminated':
                            # Get instance name from tags
                            name = 'Unknown'
                            for tag in instance.get('Tags', []):
                                if tag['Key'] == 'Name':
                                    name = tag['Value']
                                    break
                            
                            region_instances.append({
                                'id': instance['InstanceId'],
                                'name': name,
                                'state': instance['State']['Name'],
                                'type': instance['InstanceType'],
                                'launch_time': instance['LaunchTime'],
                                'region': region,
                                'public_ip': instance.get('PublicIpAddress', 'None')
                            })
                
                # Also check for instances with pentest- name pattern (backup check)
                if not region_instances:
                    response_name = ec2_client.describe_instances(
                        Filters=[
                            {'Name': 'instance-state-name', 'Values': ['running', 'pending', 'stopping', 'stopped']},
                            {'Name': 'tag:Name', 'Values': ['pentest-*']}
                        ]
                    )
                    
                    for reservation in response_name['Reservations']:
                        for instance in reservation['Instances']:
                            if instance['State']['Name'] != 'terminated':
                                name = 'Unknown'
                                for tag in instance.get('Tags', []):
                                    if tag['Key'] == 'Name':
                                        name = tag['Value']
                                        break
                                
                                if 'pentest' in name.lower():
                                    region_instances.append({
                                        'id': instance['InstanceId'],
                                        'name': name,
                                        'state': instance['State']['Name'],
                                        'type': instance['InstanceType'],
                                        'launch_time': instance['LaunchTime'],
                                        'region': region,
                                        'public_ip': instance.get('PublicIpAddress', 'None')
                                    })
                
                if region_instances:
                    print(f" Found {len(region_instances)} instance(s)! 🎯")
                    all_instances.extend(region_instances)
                else:
                    print(" Clear ✅")
                    
            except Exception as e:
                print(f" Error: {str(e)}")
                continue
        
        return all_instances
        
    except Exception as e:
        print(f"Error scanning regions: {str(e)}")
        return []

def handle_global_instances(session, all_instances):
    """Handle existing instances found across all regions"""
    if not all_instances:
        print("\n✅ No existing pentest instances found in any region!")
        return True
    
    print(f"\n⚠️  Found {len(all_instances)} existing pentest instance(s) across regions:")
    print("=" * 80)
    
    # Group by region for better display
    by_region = {}
    for inst in all_instances:
        region = inst['region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(inst)
    
    for region, instances in by_region.items():
        print(f"\n📍 Region: {region}")
        print("-" * 40)
        for i, inst in enumerate(instances, 1):
            print(f"  {i}. {inst['name']} ({inst['id']})")
            print(f"     State: {inst['state']}, Type: {inst['type']}")
            print(f"     Public IP: {inst['public_ip']}")
            print(f"     Launched: {inst['launch_time']}")
    
    print("\n" + "=" * 80)
    print("Options:")
    print("1. Terminate ALL existing instances across all regions and create new one")
    print("2. Terminate instances in SPECIFIC region only")
    print("3. Keep all existing instances and create new one")
    print("4. Exit without creating new instance")
    
    while True:
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '1':
            # Terminate all instances across all regions
            return terminate_all_instances(session, all_instances)
            
        elif choice == '2':
            # Let user select specific region to clean up
            return terminate_by_region(session, by_region)
            
        elif choice == '3':
            print("Keeping all existing instances, proceeding with new instance...")
            return True
            
        elif choice == '4':
            print("Exiting...")
            return False
            
        else:
            print("Please enter 1, 2, 3, or 4")

def terminate_all_instances(session, all_instances):
    """Terminate all instances across all regions"""
    print(f"\n🗑️  Terminating {len(all_instances)} instances across all regions...")
    
    # Group by region
    by_region = {}
    for inst in all_instances:
        region = inst['region']
        if region not in by_region:
            by_region[region] = []
        by_region[region].append(inst)
    
    success = True
    for region, instances in by_region.items():
        try:
            print(f"\nTerminating {len(instances)} instance(s) in {region}...")
            ec2_client = session.client('ec2', region_name=region)
            instance_ids = [inst['id'] for inst in instances]
            
            ec2_client.terminate_instances(InstanceIds=instance_ids)
            
            print(f"Waiting for instances in {region} to terminate...")
            waiter = ec2_client.get_waiter('instance_terminated')
            waiter.wait(InstanceIds=instance_ids)
            
            print(f"✅ All instances in {region} terminated successfully")
            
            # Clean up security groups in this region
            cleanup_orphaned_security_groups(ec2_client)
            
        except Exception as e:
            print(f"❌ Error terminating instances in {region}: {str(e)}")
            success = False
    
    return success

def terminate_by_region(session, by_region):
    """Let user select which region to clean up"""
    regions = list(by_region.keys())
    
    print(f"\nSelect region to clean up:")
    for i, region in enumerate(regions, 1):
        print(f"{i}. {region} ({len(by_region[region])} instance(s))")
    
    while True:
        try:
            choice = input(f"\nSelect region (1-{len(regions)}): ").strip()
            if not choice:
                continue
            
            index = int(choice) - 1
            if 0 <= index < len(regions):
                selected_region = regions[index]
                instances = by_region[selected_region]
                
                print(f"Terminating {len(instances)} instance(s) in {selected_region}...")
                ec2_client = session.client('ec2', region_name=selected_region)
                instance_ids = [inst['id'] for inst in instances]
                
                ec2_client.terminate_instances(InstanceIds=instance_ids)
                
                print(f"Waiting for instances to terminate...")
                waiter = ec2_client.get_waiter('instance_terminated')
                waiter.wait(InstanceIds=instance_ids)
                
                print(f"✅ All instances in {selected_region} terminated successfully")
                cleanup_orphaned_security_groups(ec2_client)
                
                return True
            else:
                print(f"Please enter a number between 1 and {len(regions)}")
        except ValueError:
            print("Please enter a valid number")
        except Exception as e:
            print(f"Error: {str(e)}")
            return False

def terminate_instances(ec2_client, instances):
    """Terminate the specified instances"""
    try:
        instance_ids = [inst['id'] for inst in instances]
        
        print(f"\nTerminating {len(instance_ids)} instance(s)...")
        ec2_client.terminate_instances(InstanceIds=instance_ids)
        
        print("Waiting for instances to terminate...")
        waiter = ec2_client.get_waiter('instance_terminated')
        waiter.wait(InstanceIds=instance_ids)
        
        print("✅ All instances terminated successfully")
        
        # Also clean up associated security groups
        cleanup_orphaned_security_groups(ec2_client)
        
        return True
        
    except Exception as e:
        print(f"Error terminating instances: {str(e)}")
        return False

def cleanup_orphaned_security_groups(ec2_client):
    """Clean up security groups from terminated pentest instances"""
    try:
        print("Cleaning up orphaned security groups...")
        
        # Get security groups with pentest- prefix
        response = ec2_client.describe_security_groups(
            Filters=[
                {'Name': 'group-name', 'Values': ['pentest-sg-*']}
            ]
        )
        
        for sg in response['SecurityGroups']:
            try:
                print(f"Deleting security group: {sg['GroupId']} ({sg['GroupName']})")
                ec2_client.delete_security_group(GroupId=sg['GroupId'])
            except Exception as e:
                print(f"Could not delete security group {sg['GroupId']}: {str(e)}")
                
    except Exception as e:
        print(f"Error cleaning up security groups: {str(e)}")

def create_ec2_instance(ec2_client, ami_id, key_name, sg_id, region):
    """Create EC2 instance"""
    instance_name = f"pentest-ubuntu-{int(time.time())}"
    
    try:
        print("Launching EC2 instance...")
        response = ec2_client.run_instances(
            ImageId=ami_id,
            MinCount=1,
            MaxCount=1,
            InstanceType='t2.micro',  # Free tier eligible
            KeyName=key_name,
            SecurityGroupIds=[sg_id],
            BlockDeviceMappings=[
                {
                    'DeviceName': '/dev/sda1',  # Root device for Ubuntu
                    'Ebs': {
                        'VolumeSize': 20,  # 20GB instead of default 8GB
                        'VolumeType': 'gp3',  # Latest generation (free tier eligible)
                        'DeleteOnTermination': True
                    }
                }
            ],
            TagSpecifications=[
                {
                    'ResourceType': 'instance',
                    'Tags': [
                        {'Key': 'Name', 'Value': instance_name},
                        {'Key': 'Purpose', 'Value': 'Pentesting'},
                        {'Key': 'Environment', 'Value': 'Lab'}
                    ]
                }
            ],
            UserData="""#!/bin/bash
# Log everything for debugging
exec > >(tee /var/log/user-data.log|logger -t user-data -s 2>/dev/console) 2>&1
echo "UserData script starting at $(date)"

# Update system
echo "Updating system packages..."
apt-get update -y
DEBIAN_FRONTEND=noninteractive apt-get upgrade -y

# Install useful tools
echo "Installing basic tools..."
apt-get install -y htop curl wget git vim nmap netcat-openbsd unzip tree

# Install Docker
echo "Installing Docker..."
apt-get remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
apt-get install -y ca-certificates curl gnupg lsb-release
mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
systemctl start docker
systemctl enable docker
usermod -aG docker ubuntu

# Add ec2-user to docker group if exists
if id "ec2-user" &>/dev/null; then
    usermod -aG docker ec2-user
    echo "Added ec2-user to docker group"
fi

# Install Python3 and pip
echo "Installing Python tools..."
apt-get install -y python3 python3-pip python3-venv

# Install additional penetration testing tools
echo "Installing additional pentest tools..."
apt-get install -y nmap masscan gobuster nikto sqlmap john hashcat hydra

# Install Go (for various security tools)
echo "Installing Go..."
wget -O /tmp/go.tar.gz https://go.dev/dl/go1.24.4.linux-amd64.tar.gz
tar -C /usr/local -xzf /tmp/go.tar.gz

# Configure Go environment for root (for installation)
echo 'export PATH=$PATH:/usr/local/go/bin' >> /root/.bashrc
echo 'export GOPATH=/root/go' >> /root/.bashrc

# Configure Go environment for ubuntu user (for usage)
echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/ubuntu/.bashrc
echo 'export GOPATH=/home/ubuntu/go' >> /home/ubuntu/.bashrc
echo 'export PATH=$PATH:/home/ubuntu/go/bin' >> /home/ubuntu/.bashrc

# Also configure for ec2-user (in case of Amazon Linux or other AMIs)
if [ -d "/home/ec2-user" ]; then
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /home/ec2-user/.bashrc
    echo 'export GOPATH=/home/ec2-user/go' >> /home/ec2-user/.bashrc
    echo 'export PATH=$PATH:/home/ec2-user/go/bin' >> /home/ec2-user/.bashrc
    mkdir -p /home/ec2-user/go/{bin,src,pkg}
    chown -R ec2-user:ec2-user /home/ec2-user/go 2>/dev/null || echo "ec2-user not found, skipping"
fi

# Create Go workspace for both users
mkdir -p /root/go/{bin,src,pkg}
mkdir -p /home/ubuntu/go/{bin,src,pkg}
chown -R ubuntu:ubuntu /home/ubuntu/go

# Install Go-based security tools
echo "Installing Go-based security tools..."
export HOME=/root
export GOCACHE=/root/.cache/go-build
export XDG_CACHE_HOME=/root/.cache
export PATH=$PATH:/usr/local/go/bin
export GOPATH=/root/go

# Create cache directories
mkdir -p $GOCACHE
mkdir -p $XDG_CACHE_HOME
mkdir -p $GOPATH/{bin,src,pkg}

# Install Nuclei with proper environment
echo "Installing Nuclei..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install other useful Go tools
echo "Installing subfinder..."
/usr/local/go/bin/go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

echo "Installing httprobe..."
/usr/local/go/bin/go install -v github.com/tomnomnom/httprobe@latest

echo "Installing ffuf..."
/usr/local/go/bin/go install -v github.com/ffuf/ffuf@latest

# Move Go tools to system PATH for all users
echo "Moving Go tools to system PATH..."
if [ -d "$GOPATH/bin" ]; then
    cp $GOPATH/bin/* /usr/local/bin/ 2>/dev/null || echo "No binaries to copy from GOPATH/bin"
fi

# Also copy to ubuntu user's Go bin for their PATH
if [ -d "$GOPATH/bin" ]; then
    cp $GOPATH/bin/* /home/ubuntu/go/bin/ 2>/dev/null || echo "No binaries to copy to ubuntu go/bin"
    chown -R ubuntu:ubuntu /home/ubuntu/go/bin/
fi

# Copy to ec2-user if exists
if [ -d "/home/ec2-user/go/bin" ]; then
    cp $GOPATH/bin/* /home/ec2-user/go/bin/ 2>/dev/null || echo "No binaries to copy to ec2-user go/bin"
    chown -R ec2-user:ec2-user /home/ec2-user/go/bin/ 2>/dev/null || true
fi

# Verify installations
echo "Verifying Go tool installations..."
/usr/local/bin/nuclei -version 2>/dev/null && echo "✅ Nuclei installed" || echo "❌ Nuclei failed"
/usr/local/bin/subfinder -version 2>/dev/null && echo "✅ Subfinder installed" || echo "❌ Subfinder failed"
/usr/local/bin/httprobe -h 2>/dev/null && echo "✅ Httprobe installed" || echo "❌ Httprobe failed"
/usr/local/bin/ffuf -V 2>/dev/null && echo "✅ Ffuf installed" || echo "❌ Ffuf failed"

# Download Nuclei templates
echo "Downloading Nuclei templates..."
if [ -f "/usr/local/bin/nuclei" ]; then
    sudo -u ubuntu /usr/local/bin/nuclei -update-templates
    # Also update for ec2-user if exists
    if id "ec2-user" &>/dev/null; then
        sudo -u ec2-user /usr/local/bin/nuclei -update-templates
    fi
else
    echo "❌ Nuclei not found, skipping template download"
fi

# Create useful directories
mkdir -p /home/ubuntu/tools
mkdir -p /home/ubuntu/wordlists
chown -R ubuntu:ubuntu /home/ubuntu/tools
chown -R ubuntu:ubuntu /home/ubuntu/wordlists

# Create directories for ec2-user if exists
if [ -d "/home/ec2-user" ]; then
    mkdir -p /home/ec2-user/tools
    mkdir -p /home/ec2-user/wordlists
    chown -R ec2-user:ec2-user /home/ec2-user/tools 2>/dev/null || true
    chown -R ec2-user:ec2-user /home/ec2-user/wordlists 2>/dev/null || true
fi

# Download essential wordlists (smaller set to avoid disk issues)
echo "Downloading essential wordlists..."
cd /home/ubuntu/wordlists

# Create essential directory
mkdir -p essential
cd essential

# Download key wordlists only (much smaller than full SecLists)
echo "Downloading common web wordlists..."
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt -O common.txt
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt -O directory-list-medium.txt
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt -O top-1000-passwords.txt
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/big.txt -O big.txt

# Download some additional useful lists
echo "Downloading additional wordlists..."
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Usernames/Names/names.txt -O usernames.txt
wget -q https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt -O subdomains-5k.txt

echo "✅ Essential wordlists downloaded"
chown -R ubuntu:ubuntu /home/ubuntu/wordlists

# Check disk space after download
echo "Disk space check:"
df -h / | tail -1

# Create a simple web server service
echo "Setting up web server..."
mkdir -p /var/www/html
cat > /var/www/html/index.html << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Pentest Lab Server</title>
    <style>
        body { font-family: Arial; margin: 40px; background: #f0f0f0; }
        .container { background: white; padding: 20px; border-radius: 8px; }
        .status { color: green; font-weight: bold; }
        .tools { background: #f9f9f9; padding: 15px; margin: 10px 0; border-radius: 4px; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔧 Pentest Lab Server Ready!</h1>
        <p class="status">✅ SSH and web services are running</p>
        
        <div class="tools">
            <h3>Installed Tools:</h3>
            <ul>
                <li>Docker + Docker Compose</li>
                <li>Python3 + pip</li>
                <li>nmap, masscan, gobuster</li>
                <li>nikto, sqlmap, john, hashcat</li>
                <li>hydra, aircrack-ng</li>
                <li>SecLists wordlists</li>
                <li>Nuclei vulnerability scanner + templates</li>
                <li>subfinder, httprobe, ffuf (Go tools)</li>
            </ul>
        </div>
        
        <p><strong>Server Info:</strong><br>
        Ubuntu 24.04.2 LTS<br>
        Instance Type: t2.micro (Free Tier)<br>
        Time: $(date)
        </p>
    </div>
</body>
</html>
EOF

# Create systemd service for web server
cat > /etc/systemd/system/pentest-web.service << 'EOF'
[Unit]
Description=Pentest Lab Web Server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/var/www/html
ExecStart=/usr/bin/python3 -m http.server 80
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl enable pentest-web.service
systemctl start pentest-web.service

# Create a welcome script for SSH login
cat > /etc/motd << 'EOF'

🔧 PENTEST LAB SERVER
===================
Welcome to your penetration testing environment!

📋 Quick Commands:
  - docker --version        # Check Docker installation
  - python3 --version       # Check Python
  - go version              # Check Go installation
  - nuclei -version          # Check Nuclei scanner
  - ls ~/wordlists          # View wordlists
  - ls ~/tools              # Your tools directory
  - ls ~/go                 # Go workspace

🛠️  Installed Tools:
  - nmap, masscan, gobuster, nikto
  - sqlmap, john, hashcat, hydra
  - Nuclei with templates (vulnerability scanner)
  - subfinder, httprobe, ffuf
  - Docker with compose plugin
  - Go 1.21.5 programming language
  - SecLists wordlists in ~/wordlists

🌐 Web Interface: http://[your-ip]/

Happy hacking! 🔒

EOF

# Final setup
echo "Running final setup tasks..."
# Ensure docker works for ubuntu user
systemctl restart docker
sleep 5

# Test installations
echo "Testing installations..."
docker --version >> /var/log/user-data.log
python3 --version >> /var/log/user-data.log
/usr/local/go/bin/go version >> /var/log/user-data.log
/usr/local/bin/nuclei -version >> /var/log/user-data.log 2>&1 || echo "Nuclei not found" >> /var/log/user-data.log
nmap --version | head -2 >> /var/log/user-data.log

echo "UserData script completed at $(date)" >> /var/log/user-data.log
echo "Setup complete! Check /var/log/user-data.log for details"
"""
        )
        
        instance_id = response['Instances'][0]['InstanceId']
        print(f"✅ Instance launched: {instance_id}")
        
        # Wait for instance to be running
        print("Waiting for instance to be running...")
        waiter = ec2_client.get_waiter('instance_running')
        waiter.wait(InstanceIds=[instance_id])
        
        # Get instance details
        response = ec2_client.describe_instances(InstanceIds=[instance_id])
        instance = response['Reservations'][0]['Instances'][0]
        
        return {
            'instance_id': instance_id,
            'public_ip': instance.get('PublicIpAddress'),
            'public_dns': instance.get('PublicDnsName'),
            'name': instance_name
        }
        
    except Exception as e:
        print(f"Error creating EC2 instance: {str(e)}")
        return None

def display_connection_info(instance_info, ssh_key, region):
    """Display connection information"""
    print("\n" + "=" * 60)
    print("🚀 EC2 INSTANCE LAUNCHED!")
    print("=" * 60)
    print(f"Instance ID: {instance_info['instance_id']}")
    print(f"Instance Name: {instance_info['name']}")
    print(f"Region: {region}")
    print(f"Public IP: {instance_info['public_ip']}")
    print(f"Public DNS: {instance_info['public_dns']}")
    
    print("\n⏱️  INSTALLATION STATUS:")
    print("-" * 30)
    print("🔄 UserData script is currently running in the background")
    print("📦 Installing tools: Docker, Go, Nuclei, wordlists, etc.")
    print("⌛ Please wait 5-8 minutes for complete installation")
    print("📋 You can monitor progress by checking the installation log")
    
    print("\n📡 CONNECTION COMMANDS:")
    print("-" * 30)
    print(f"SSH Connection:")
    print(f"ssh -i {ssh_key['private_key_path']} ubuntu@{instance_info['public_ip']}")
    print(f"\nWeb Access (available after installation):")
    print(f"http://{instance_info['public_ip']}")
    print(f"\nAWS Console:")
    print(f"https://console.aws.amazon.com/ec2/v2/home?region={region}#Instances:instanceId={instance_info['instance_id']}")
    
    print("\n🔍 CHECK INSTALLATION PROGRESS:")
    print("-" * 30)
    print("# SSH into the instance and run:")
    print("sudo tail -f /var/log/user-data.log")
    print("# Or check if installation is complete:")
    print("sudo cloud-init status")
    print("# Quick tool check:")
    print("./check_install.sh")
    
    print("\n🛠️  TOOLS BEING INSTALLED:")
    print("-" * 30)
    print("- Docker + Docker Compose")
    print("- Python3/pip + Go 1.21.5")
    print("- Security tools: nmap, masscan, gobuster, nikto")
    print("- Password tools: john, hashcat, hydra, sqlmap")
    print("- Nuclei vulnerability scanner + templates")
    print("- Go tools: subfinder, httprobe, ffuf")
    print("- Essential wordlists from SecLists")
    print("- Web server with status page")
    
    print("\n⚠️  IMPORTANT NOTES:")
    print("-" * 30)
    print("🕐 Wait 5-8 minutes before using tools - installation in progress")
    print("💰 This instance will incur charges if you exceed free tier limits")
    print("🗑️  Remember to terminate when done testing")
    print("📊 Free tier includes 750 hours per month of t2.micro usage")
    print("📏 20GB EBS storage is within the 30GB free tier limit")
    
    print("\n✅ READY TO USE WHEN:")
    print("-" * 30)
    print("- Web page shows 'Pentest Lab Server Ready!' at http://{}")
    print("- SSH login shows custom MOTD with tool list")
    print("- Command 'nuclei -version' works")
    print("- Docker runs: 'docker run hello-world'")
    
    print("\n🔧 QUICK START AFTER INSTALLATION:")
    print("-" * 30)
    print("# Test Nuclei")
    print("nuclei -u https://example.com")
    print("# Run a quick nmap scan")
    print("nmap -sV scanme.nmap.org")
    print("# Check wordlists")
    print("ls ~/wordlists/essential/")
    print("# Start a container")
    print("docker run -it --rm ubuntu:latest")
    
    print("=" * 60)
    
    # Format the web URL
    return instance_info['public_ip']

def main():
    print("🔧 AWS EC2 FREE TIER PENTEST LAB SETUP")
    print("=" * 60)
    
    try:
        # Create AWS session
        session = boto3.Session(profile_name=AWS_PROFILE)
        
        # Show account info
        get_account_info(session)
        
        # FIRST: Check ALL regions for existing pentest instances
        all_existing_instances = check_all_regions_for_instances(session)
        
        # Handle any existing instances found
        if not handle_global_instances(session, all_existing_instances):
            sys.exit(0)
        
        # Get user confirmation to proceed
        print("\n⚠️  Ready to create a new pentest instance")
        confirm = input("Continue with instance creation? (y/N): ").strip().lower()
        if confirm != 'y':
            print("Aborted.")
            sys.exit(0)
        
        # Select region
        region = select_region(session)
        print(f"Selected region: {region}")
        
        # Select SSH key
        ssh_key = select_ssh_key()
        print(f"Selected SSH key: {ssh_key['name']}")
        
        # Read public key content
        with open(ssh_key['public_key_path'], 'r') as f:
            public_key_content = f.read().strip()
        
        # Create EC2 client for selected region
        ec2_client = session.client('ec2', region_name=region)
        
        # Get Ubuntu AMI
        ami_id = get_ubuntu_ami(ec2_client, region)
        if not ami_id:
            print("❌ Could not find Ubuntu AMI")
            sys.exit(1)
        
        # Create/import key pair
        key_name = create_key_pair(ec2_client, ssh_key['name'], public_key_content)
        if not key_name:
            print("❌ Failed to create key pair")
            sys.exit(1)
        
        # Create security group
        sg_id = create_security_group(ec2_client, region)
        if not sg_id:
            print("❌ Failed to create security group")
            sys.exit(1)
        
        # Create EC2 instance
        instance_info = create_ec2_instance(ec2_client, ami_id, key_name, sg_id, region)
        if not instance_info:
            print("❌ Failed to create EC2 instance")
            sys.exit(1)
        
        # Display connection info
        display_connection_info(instance_info, ssh_key, region)
        
    except KeyboardInterrupt:
        print("\n\n🛑 Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Error: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()
