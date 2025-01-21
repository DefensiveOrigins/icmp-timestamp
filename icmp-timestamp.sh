#!/bin/bash

# convert milliseconds to people time
timestamp_to_human_readable() {
  local ms=$1
  local hours=$((ms / 3600000))
  local minutes=$(((ms % 3600000) / 60000))
  local seconds=$(((ms % 60000) / 1000))
  local milliseconds=$((ms % 1000))
  printf "%02d:%02d:%02d.%03d" $hours $minutes $seconds $milliseconds
}

# Get the current UTC 
today_date=$(date -u +"%Y-%m-%d")

# Read hping3 ICMP timestamp response.  This can probobably be done lots of better ways, but, heres a fast and dirty way
read -p "Enter ICMP timestamp response (e.g., Originate=xxxx Receive=yyyy Transmit=zzzz): " icmp_response

# Extract Originate, Receive, and Transmit timestamps using regex
originate=$(echo "$icmp_response" | grep -oP 'Originate=\K\d+')
receive=$(echo "$icmp_response" | grep -oP 'Receive=\K\d+')
transmit=$(echo "$icmp_response" | grep -oP 'Transmit=\K\d+')

# Check if values were extracted
if [[ -z $originate || -z $receive || -z $transmit ]]; then
  echo "Error: Unable to extract timestamps. Ensure input format is correct."
  exit 1
fi

# math time 
# Calculate RTT 
rtt=$((transmit - originate))

# Calculate local receive time
local_receive_time=$((originate + rtt))

# Calculate remote system time as the middle of Receive and Transmit
remote_system_time=$(((receive + transmit) / 2))

# Convert remote system time to people time
remote_time_human=$(timestamp_to_human_readable $remote_system_time)

# Combine with current UTC date
remote_datetime_utc="${today_date}T${remote_time_human}Z"

# Output results
cat <<EOF
Parsed ICMP Timestamps:
  Originate: $originate
  Receive:   $receive
  Transmit:  $transmit
  RTT:       ${rtt} ms

Remote System Time:
  Milliseconds since midnight UTC: $remote_system_time
  Human-readable time:             $remote_time_human
  Full UTC datetime:               $remote_datetime_utc
EOF
