# AWS EC2 Pentesting Lab Setup Script

Automatically create and configure a free-tier AWS EC2 instance with pre-installed penetration testing tools. This script is designed for cybersecurity professionals, researchers, and students who need a quick, disposable testing environment.

## 🎯 Features

### **Automated Instance Management**
- **Global Instance Scanning**: Checks ALL AWS regions for existing pentest instances
- **Smart Cleanup Options**: Terminate by region or globally before creating new instances
- **Multi-Region Support**: Deploy to any AWS region
- **Cost Management**: Prevents accidental multiple instances running

### **Pre-Configured Pentesting Environment**
- **Ubuntu 22.04 LTS** on t2.micro (free tier eligible)
- **20GB EBS storage** (within 30GB free tier limit)
- **Open security groups** for SSH (22), HTTP (80), and HTTPS (443)
- **5-8 minute automated setup** via UserData script

### **Comprehensive Tool Suite**

#### **Core Tools**
- **Docker** + Docker Compose for containerized testing
- **Python 3** + pip for scripting
- **Go 1.21.5** for building security tools
- **Git, vim, htop** for system management

#### **Network & Web Testing**
- **nmap** - Network discovery and security auditing
- **masscan** - High-speed port scanner
- **gobuster** - Directory/file brute forcer
- **nikto** - Web vulnerability scanner

#### **Vulnerability Assessment**
- **Nuclei** - Modern vulnerability scanner with templates
- **sqlmap** - SQL injection testing tool
- **subfinder** - Subdomain discovery
- **httprobe** - HTTP service probe
- **ffuf** - Fast web fuzzer

#### **Password & Credential Testing**
- **john** - Password cracker
- **hashcat** - Advanced password recovery
- **hydra** - Login brute forcer

#### **Wordlists & Resources**
- **Essential SecLists** - Curated wordlists for:
  - Web content discovery
  - Password attacks
  - Username enumeration
  - Subdomain brute forcing

## 🚀 Quick Start

### Prerequisites

1. **AWS Account** with appropriate permissions
2. **AWS CLI** configured with credentials
3. **Python 3** and **boto3** library
4. **SSH key pair** in `~/.ssh/` directory

### Installation

```bash
# Clone the repository
git clone https://github.com/random-robbie/ec2-pentest-setup.git
cd ec2-pentest-setup

# Install Python dependencies
pip install boto3

# Ensure AWS credentials are configured
aws configure --profile default

# Make sure you have SSH keys
ls ~/.ssh/*.pub
# If no keys exist, create them:
ssh-keygen -t rsa -b 4096 -f ~/.ssh/pentest_key
```

### Usage

```bash
# Run the setup script
python3 setup_ec2.py
```

### Interactive Setup Process

1. **Account Verification**: Review AWS account details and confirm
2. **Global Instance Check**: Script scans all regions for existing pentest instances
3. **Cleanup Options** (if existing instances found):
   - Terminate all instances across all regions
   - Terminate instances in specific region only
   - Keep existing and create new
   - Exit without changes
4. **Region Selection**: Choose deployment region from available options
5. **SSH Key Selection**: Pick from available SSH keys in `~/.ssh/`
6. **Instance Creation**: Automated setup with 20GB storage and security groups

## 📋 Post-Deployment

### Connection Information

After successful deployment, you'll receive:

```bash
# SSH Connection
ssh -i ~/.ssh/your_key ubuntu@your_public_ip

# Web Interface
http://your_public_ip

# AWS Console Link
https://console.aws.amazon.com/ec2/...
```

### Installation Progress

The setup takes **5-8 minutes**. Monitor progress:

```bash
# SSH into instance and check installation log
sudo tail -f /var/log/user-data.log

# Check cloud-init status
sudo cloud-init status

# Quick tool verification
./check_install.sh
```

### Ready Indicators

✅ **Installation Complete When**:
- Web page shows "Pentest Lab Server Ready!"
- SSH login displays custom MOTD with tool list
- `nuclei -version` command works
- `docker run hello-world` succeeds

## 🛠️ Using the Tools

### Quick Start Commands

```bash
# Test Nuclei vulnerability scanner
nuclei -u https://example.com

# Run network scan
nmap -sV scanme.nmap.org

# Directory brute force
gobuster dir -u https://example.com -w ~/wordlists/essential/common.txt

# Subdomain discovery
subfinder -d example.com

# Web fuzzing
ffuf -u https://example.com/FUZZ -w ~/wordlists/essential/directory-list-medium.txt

# Start Docker container
docker run -it --rm ubuntu:latest

# Check available wordlists
ls ~/wordlists/essential/
```

### Tool Locations

```bash
# System-wide binaries
/usr/local/bin/nuclei
/usr/local/bin/subfinder
/usr/local/bin/httprobe
/usr/local/bin/ffuf

# User Go tools
~/go/bin/

# Wordlists
~/wordlists/essential/

# Working directories
~/tools/        # Your custom tools
~/wordlists/    # Wordlist collections
```

## 💰 Cost Management

### Free Tier Compliance

- **Instance**: t2.micro (750 hours/month free)
- **Storage**: 20GB EBS (within 30GB/month free tier)
- **Data Transfer**: First 1GB/month free

### Cost Monitoring

```bash
# Check instance hours usage
aws ce get-cost-and-usage --time-period Start=2024-06-01,End=2024-06-30 --granularity MONTHLY --metrics BlendedCost

# Terminate when done testing
aws ec2 terminate-instances --instance-ids i-your-instance-id

# Or use the cleanup script
python3 ../clean-aws/cleanup.py
```

## 🔧 Advanced Configuration

### Custom Tool Installation

```bash
# SSH into instance
ssh -i ~/.ssh/your_key ubuntu@your_ip

# Install additional Go tools
go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# Install Python tools
pip3 install --user dirsearch

# Install via package manager
sudo apt install -y metasploit-framework
```

### Docker Pentesting

```bash
# Run Kali Linux container
docker run -it --rm kalilinux/kali-rolling

# Run OWASP ZAP
docker run -p 8080:8080 -d owasp/zap2docker-stable zap-webswing.sh

# Run custom tools in containers
docker run -v $(pwd):/data -it ubuntu:latest
```

### Storage Management

```bash
# Check disk usage
df -h

# Clean up Docker images
docker system prune -a

# Remove old wordlists
rm -rf ~/wordlists/old_lists/
```

## 🔒 Security Considerations

### **Production Safety**
- ⚠️ **NEVER run on production accounts**
- ✅ **Always verify account information** before proceeding
- 🔍 **Review security group rules** - they allow global access
- 🗑️ **Terminate instances** when not in use

### **Network Security**
- Instance allows **SSH from anywhere** (0.0.0.0/0)
- Instance allows **HTTP/HTTPS from anywhere** (0.0.0.0/0)
- Consider **restricting source IPs** for production use
- Use **VPN or bastion hosts** for sensitive testing

### **Data Protection**
- 💾 **No persistent data** - instance storage is ephemeral
- 🔑 **Protect SSH keys** - don't commit to repositories
- 📊 **Monitor costs** - unexpected charges may indicate compromise

## 🐛 Troubleshooting

### Common Issues

**Instance Not Responding**
```bash
# Check instance status
aws ec2 describe-instance-status --instance-ids i-your-instance

# Check security groups
aws ec2 describe-security-groups --group-ids sg-your-sg-id
```

**Tools Not Working**
```bash
# Check installation log
sudo cat /var/log/user-data.log | grep -i error

# Manually install missing tools
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
sudo cp ~/go/bin/nuclei /usr/local/bin/
```

**Disk Space Issues**
```bash
# Check space
df -h

# Clean up
sudo apt autoremove -y
docker system prune -f
```

**SSH Connection Failed**
```bash
# Verify key permissions
chmod 600 ~/.ssh/your_private_key

# Test connection with verbose output
ssh -v -i ~/.ssh/your_key ubuntu@your_ip
```

### **Getting Help**

1. **Check the logs**: `sudo tail -f /var/log/user-data.log`
2. **Verify AWS permissions**: Ensure your user can create EC2 instances
3. **Review security groups**: Confirm ports 22, 80, 443 are open
4. **Test from different network**: Try from different IP/location

## 📚 Additional Resources

### **Learning & Documentation**
- [AWS Free Tier Guide](https://aws.amazon.com/free/)
- [Nuclei Templates](https://github.com/projectdiscovery/nuclei-templates)
- [SecLists Wordlists](https://github.com/danielmiessler/SecLists)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

### **Related Projects**
- [AWS Cleanup Script](https://github.com/random-robbie/clean-aws) - Companion cleanup tool
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [ProjectDiscovery Tools](https://github.com/projectdiscovery) - Security tool suite

## 🤝 Contributing

Contributions welcome! Please:

1. **Fork the repository**
2. **Create feature branch**: `git checkout -b feature/new-tool`
3. **Test thoroughly** in your AWS environment
4. **Submit pull request** with detailed description

### **Enhancement Ideas**
- Additional security tools
- Different Linux distributions
- Custom AMI creation
- Integration with CI/CD pipelines
- Automated report generation

## 📄 License

MIT License - see LICENSE file for details

## ⚠️ Disclaimer

This tool is provided for **legitimate security testing and educational purposes only**. Users are responsible for:

- Ensuring proper authorization before testing
- Complying with applicable laws and regulations  
- Managing AWS costs and resource usage
- Securing their testing environment appropriately

The authors are not responsible for misuse, unauthorized access, or associated costs.

---

**Happy Hunting! 🔍🛡️**
