#!/bin/bash

# Function to print the CVE banner
print_banner() {
  echo "#################################################"
  echo "#     CVE-1999-0524 - Remote Date Disclosure    #"
  echo "#          Created By DefensiveOrigins          #"
  echo "#################################################"
}

# Check if the -s flag is passed (to suppress the banner)
suppress_banner=0
while getopts "O:R:T:u:hs" opt; do
  case ${opt} in
    O)
      originate=$OPTARG
      ;;
    R)
      receive=$OPTARG
      ;;
    T)
      transmit=$OPTARG
      ;;
    u)
      today_date=$OPTARG
      ;;
    h)
      usage
      ;;
    s)
      suppress_banner=1
      ;;
    *)
      usage
      ;;
  esac
done

# If the -s flag is not set, print the banner
if [ $suppress_banner -eq 0 ]; then
  print_banner
fi

# Convert milliseconds to human-readable time
timestamp_to_human_readable() {
  local ms=$1
  local hours=$((ms / 3600000))
  local minutes=$(((ms % 3600000) / 60000))
  local seconds=$(((ms % 60000) / 1000))
  local milliseconds=$((ms % 1000))
  printf "%02d:%02d:%02d.%03d" $hours $minutes $seconds $milliseconds
}

# Get the current UTC date
today_date=$(date -u +"%Y-%m-%d")

# Function to show usage instructions
usage() {
  echo "Usage: $0 -O <Originate timestamp> -R <Receive timestamp> -T <Transmit timestamp>"
  echo "Optional Flags:"
  echo "  -h                       Show this help message"
  echo "  -O <Originate timestamp>  The Originate timestamp (required)"
  echo "  -R <Receive timestamp>    The Receive timestamp (required)"
  echo "  -T <Transmit timestamp>   The Transmit timestamp (required)"
  echo "  -u <UTC date>             Custom UTC date in format YYYY-MM-DD (optional, default is current UTC)"
  echo "  -s                       Suppress the CVE banner"
  exit 1
}

# Ensure all required arguments are provided
if [[ -z $originate || -z $receive || -z $transmit ]]; then
  echo "Error: All timestamps (-O, -R, -T) are required."
  usage
fi

# Convert inputs to numeric values, handling any .0 values
originate_value=$(echo $originate | sed 's/\.0$//')
receive_value=$(echo $receive | sed 's/\.0$//')
transmit_value=$(echo $transmit | sed 's/\.0$//')

# Check if any timestamps are zero or zero point zero and output message accordingly
if [[ "$originate_value" == "0" && "$receive_value" == "0" && "$transmit_value" == "0" ]]; then
  # Set Blue color for the ! symbol
  BLUE='\033[0;34m'
  RESET='\033[0m'
  echo -e "[${BLUE}!${RESET}] Host not Vulnerable"
  exit 0
fi

# Calculate RTT
rtt=$((transmit - originate))

# Calculate local receive time
local_receive_time=$((originate + rtt))

# Calculate remote system time as the middle of Receive and Transmit
remote_system_time=$(((receive + transmit) / 2))

# Convert remote system time to human-readable format
remote_time_human=$(timestamp_to_human_readable $remote_system_time)

# Combine with the current UTC date
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
