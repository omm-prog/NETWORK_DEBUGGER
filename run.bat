@echo off
REM Run the network debugger (change interface name as needed)
python -m netdbg_win --iface "Ethernet" --filter "tcp"
pause