# ScanX

Commands

### 1. Clone the Repository

```bash
git clone https://github.com/hardeep12341/scanx.git
```

### 2. Enter the Project Directory

```bash
cd scanx
```

### 3. Run ScanX

```bash
python3 scanx.py
```

### 4. Check Python Version

```bash
python3 --version
```

ScanX requires **Python 3.9 or newer**.

### 5. Make ScanX Executable *(Optional — Linux/Kali)*

```bash
chmod +x scanx.py
```

Then run:

```bash
./scanx.py
```

### 6. Start a Scan

After starting ScanX:

```text
python3 scanx.py
```

Select an option from the menu:

```text
1. Quick Port Scan
2. Top Ports + Service Detection
3. Full TCP Port Scan
4. Custom Port Scan
5. Comprehensive Security Scan
6. Exit
```

Enter your authorized target when prompted:

```text
Target IP / hostname: 192.168.1.10
```

### 7. Custom Port Range

When using **Custom Port Scan**, enter ports such as:

```text
22,80,443,8080
```

or a range:

```text
1-1000
```

or a combination:

```text
22,80,443,8000-8100
```

### 8. View Generated Reports

ScanX saves scan results as:

```text
JSON
CSV
TXT
```

Reports can be found in:

```text
pyscan_reports/
```

Example:

```bash
ls -lah pyscan_reports/
```

> **Note:** Replace `YOUR_USERNAME` with your GitHub username. Only scan systems you own or have explicit permission to test.
