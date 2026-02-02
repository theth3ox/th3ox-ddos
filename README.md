# 🔥 th3ox DDoS - Multi Tool

<p align="center">
  <img src="https://img.shields.io/badge/version-1.0-blue?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/python-3.x-green?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/methods-11-red?style=for-the-badge" alt="Methods">
  <img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge" alt="License">
</p>

**Author:** th3ox  
**Language:** Python 3.x  
**Tools:** 11 Attack Methods + 3 Utilities

---

## ⚠️ Legal Disclaimer
This tool is for **educational and authorized testing purposes only**.  
Unauthorized use against systems you do not own or have explicit permission to test is **illegal**.  
The author is **not responsible** for any misuse or damage caused by this software.  
**USE AT YOUR OWN RISK.**

---

## 🚀 Features

**11 Attack Methods + 3 Tools**

### Layer7 (Web Attacks)
- **GET** - HTTP GET flood
- **POST** - HTTP POST flood
- **STRESS** - High bandwidth attack
- **SLOW** - Slowloris attack
- **CFB** - CloudFlare bypass
- **CFBUAM** - CloudFlare UnderAttack mode bypass
- **BYPASS** - Generic bypass

### Layer4 (Network Attacks)
- **TCP** - TCP flood
- **UDP** - UDP flood
- **SYN** - SYN flood (requires admin)
- **ICMP** - ICMP flood (requires admin)

### Tools
- **CHECK** - Website status checker
- **PING** - Ping utility
- **DNS** - DNS lookup (coming soon)

---

## 📦 Installation

### 🪟 Windows

#### Simple Installation (Recommended)
```powershell
# Clone or download repository
git clone https://github.com/th3ox/th3ox-ddos.git
cd th3ox-ddos

# Install all dependencies (PyRoxy included)
pip install -r requirements.txt

# Run
python start.py
```

#### If Installation Fails
```powershell
# Install dependencies one by one
pip install cloudscraper certifi dnspython requests psutil icmplib pyasn1 yarl
pip install https://github.com/MatrixTM/PyRoxy/archive/refs/heads/master.zip

# Run
python start.py
```

---
cd th3ox-ddos

# Install all dependencies (PyRoxy included)
pip install -r requirements.txt

python start.py
```

---

### 🐧 Linux

#### Simple Installation (Recommended)
```bash
# Update system & install dependencies
sudo apt update && sudo apt install -y python3 python3-pip git

# Clone repository
git clone https://github.com/th3ox/th3ox-ddos.git
cd th3ox-ddos

# Install all dependencies (PyRoxy included)
pip3 install -r requirements.txt

# Run
python3 start.py
```

#### One-Line Install
```bash
sudo apt update && sudo apt install -y python3 python3-pip git && git clone https://github.com/th3ox/th3ox-ddos.git && cd th3ox-ddos && pip3 install -r requirements.txt && python3 start.py
```

---

### 🍎 macOS

#### Simple Installation (Recommended)
```bash
# Install Homebrew (if not installed)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python & Git
brew install python3 git

# Clone repository
git clone https://github.com/th3ox/th3ox-ddos.git
cd th3ox-ddos

# Install all dependencies (PyRoxy included)
pip3 install -r requirements.txt

# Run
python3 start.py
```

#### One-Line Install
```bash
brew install python3 git && git clone https://github.com/th3ox/th3ox-ddos.git && cd th3ox-ddos && pip3 install -r requirements.txt && python3 start.py
```

---

### ⚠️ Important Notes:
- **SYN & ICMP attacks** require:
  1. **Administrator/root privileges**
  2. **Impacket package** (optional, install separately if needed)
     - Windows: `pip install impacket --user`
     - Linux/macOS: `sudo pip3 install impacket`
- **All other methods work without impacket**
- Linux/macOS: Use `sudo python3 start.py` for SYN/ICMP
- Windows: Run PowerShell/CMD as Administrator for SYN/ICMP
- Python **3.7+** required

---

## 🎯 Usage

### Interactive Mode (Recommended)
```bash
python start.py
```
Then follow the menu:
1. Choose attack type (Layer7/Layer4/Tools)
2. Select method
3. Enter target
4. Configure proxy (optional for Layer7)
5. Set threads & duration

### Command Line Mode
```bash
# Layer7
python start.py GET http://example.com 5 500 proxies.txt 100 60

# Layer4
python start.py TCP 1.2.3.4:80 500 60

# Tools
python start.py CHECK
```

---

## 🛡️ Safety Features
- Blocks localhost attacks (127.0.0.1, ::1)
- Blocks private networks (10.x, 192.168.x, 172.16-31.x)
- Prevents self-attack

---

## 📝 Notes
- Proxy files auto-download if missing
- Requires admin for raw socket methods (SYN, ICMP)
- Legal authorization required before use

---

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**© 2026 th3ox - All rights reserved**

