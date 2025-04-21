#!/bin/bash
# Test script for Security Event Logger in sudo mode

echo "Starting Security Event Logger tests..."
echo "This script must be run with sudo in a separate terminal."

# First, start the Security Event Logger with proper display permissions
echo "Please ensure you've started the Security Event Logger with:"
echo "xhost +local:root"
echo "sudo -E QT_QPA_PLATFORM=xcb /home/aman/security_event_logger/venv/bin/python /home/aman/security_event_logger/gui.py"
echo ""
echo "Press Enter to continue with tests..."
read

# Generate authentication events
echo "=== Testing Authentication Events ==="
echo "Creating invalid login attempt..."
ssh nonexistent_user@localhost &> /dev/null || true
echo "Done"

# Generate password events
echo "=== Testing Password/Sudo Events ==="
echo "Executing sudo command..."
sudo ls -la /root &> /dev/null
echo "Done"

# Generate file system events in protected directories
echo "=== Testing Protected File System Events ==="
echo "Creating file in /etc..."
sudo touch /etc/security_logger_test_file
echo "Modifying file in /etc..."
sudo echo "test content" | sudo tee /etc/security_logger_test_file &> /dev/null
echo "Removing file from /etc..."
sudo rm /etc/security_logger_test_file
echo "Done"

# Generate network events
echo "=== Testing Network Events ==="
echo "Creating network connections..."
sudo nmap -sT -p 22,80,443 localhost &> /dev/null
echo "Done"

# Generate process events including suspicious commands
echo "=== Testing Suspicious Process Events ==="
echo "Running suspicious commands..."
sudo find / -name "*.log" -type f -mtime -1 | head -n 1 &> /dev/null
sudo wget -q --spider http://example.com
echo "Done"

# Test service control (requires root)
echo "=== Testing Service Events ==="
echo "Stopping and starting a service..."
SERVICE="systemd-timesyncd"
sudo systemctl stop $SERVICE
sleep 1
sudo systemctl start $SERVICE
echo "Done"

echo ""
echo "All tests completed! Check the Security Event Logger GUI to verify events were captured."
echo "You should see:"
echo "1. Authentication failure events"
echo "2. Sudo command execution events"
echo "3. File creation/modification/deletion in /etc"
echo "4. Network connection events including nmap (flagged as suspicious)"
echo "5. Suspicious commands (wget, find)"
echo "6. Service start/stop events"
echo ""
echo "These events would NOT be fully visible when running in normal user mode."