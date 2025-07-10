# Ransomware Simulator (Educational Use Only)

A safe, simulated ransomware demonstration tool for cybersecurity education.

## **⚠️ WARNING**
- **FOR EDUCATIONAL USE ONLY**
- **DO NOT use on real systems without permission**
- **Unauthorized use may be illegal**

---

## **📋 Requirements**
- Kali Linux (or any Linux with Python)
- Python 3.x
- `tkinter` (for GUI)
- `cryptography` module

---

## **🚀 Setup & Usage**

### **1. Create a Virtual Environment (Recommended)**
```bash
# Install virtualenv if not installed
sudo apt install python3-virtualenv
```
# Create a virtual environment
```bash
virtualenv venv
```
# Activate it
```bash
source venv/bin/activate
```
# Install Dependencies
```bash
pip install cryptography
```
# Create a Test Directory
```bash
mkdir ~/ransomware_test
cd ~/ransomware_test
touch file1.txt file2.txt
echo "Test file for ransomware simulation." > file1.txt
echo "This is a safe educational demo." > file2.txt
```
# Run the Simulator
```bash
python3 ransomware_simulator.py
```
