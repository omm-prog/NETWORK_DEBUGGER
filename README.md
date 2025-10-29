# Network Debugger

A Windows network traffic monitoring tool that captures and displays TCP/UDP packets in real-time.

## Installation

1. Install required dependencies:
```bash
pip install pydivert psutil tabulate
```

2. Navigate to the project directory:
```bash
cd "C:\Users\<YourName>\Desktop\NETWORK DEBUGGER"
```

3. Run the network debugger:
```bash
python -m netdbg_win --filter "tcp or udp"
```

## Requirements

- Windows OS
- Python 3.x
- Administrator privileges (required for packet capture)

## Note

Replace `<YourName>` with your actual Windows username in the installation path.
