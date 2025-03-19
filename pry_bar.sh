#!/bin/bash

# Loop through each IP in the file
for IP in $(cat icmp-timestamp-hosts.txt); do
  # Run the hping3 command and capture the output
  output=$(hping3 "$IP" --icmp --icmp-ts -V -c 1)

  # Extract the round-trip times (min/avg/max) from the hping3 output
  rtt_min=$(echo "$output" | grep -oP 'round-trip min/avg/max = \K[0-9.]+(?=/)')
  rtt_avg=$(echo "$output" | grep -oP 'round-trip min/avg/max = [0-9.]+/\K[0-9.]+(?=/)')
  rtt_max=$(echo "$output" | grep -oP 'round-trip min/avg/max = [0-9.]+/[0-9.]+/\K[0-9.]+')

  # If any of the RTT values are empty, default to 0
  rtt_min=${rtt_min:-0.0}
  rtt_avg=${rtt_avg:-0.0}
  rtt_max=${rtt_max:-0.0}

  # Optionally, you can print the extracted RTT values
  echo "IP: $IP - RTT Min: $rtt_min ms, RTT Avg: $rtt_avg ms, RTT Max: $rtt_max ms"

  # Run the test.sh script with the extracted RTT values as arguments
  bash ./icmp-timestamp.sh -O "$rtt_min" -R "$rtt_avg" -T "$rtt_max"
done
