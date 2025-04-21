#!/bin/bash

# Detect display server
if [ -n "$WAYLAND_DISPLAY" ]; then
  PLATFORM="wayland"
  echo "Detected Wayland display server"
else
  PLATFORM="xcb"
  # Grant X access to root
  xhost +local:root
  echo "Detected X11 display server"
fi

# Launch with proper environment
sudo -E QT_QPA_PLATFORM=$PLATFORM /home/aman/security_event_logger/venv/bin/python /home/aman/security_event_logger/gui.py

# Restore X server security when done
if [ "$PLATFORM" = "xcb" ]; then
  xhost -local:root
fi