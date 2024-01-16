# IPTABLES DEBUG

[Github Repo](https://github.com/jqknono/iptables_debug_tool)

Packet capture logs are a method for debugging firewall rules. However, capturing packets often results in many irrelevant entries. There are two ways to only capture specific packets: whitelist mode and blacklist mode.

- Whitelist mode: This mode only captures packets that meet certain criteria. You need to construct the packets yourself, typically only needing to create SYN packets. However, ensure to use conntrack -F to clear established connections before each test.
- Blacklist mode: This mode involves first collecting a period of inactivity logs and adding the traffic from these logs to the ignore list. This ensures the integrity of the logs during operations.

**The method that captures the most complete packet path is the blacklist mode, but it's more complex to set up.** Modify the `black_apply_default_rule` function as needed.

This script aids in implementing both packet capture modes.

## Whitelist Mode

Dependencies:

- hping3:
  - CentOS: `yum -y install epel-release & yum -y install hping3 conntrack`
  - Ubuntu 20.04: `apt-get -y install hping3 conntrack`
  - Ubuntu 22.04: `apt-get -y install hping3 conntrack iptables`

### Based on Data Length

Note that the packet length may change during transmission, causing the packet path to be incomplete. For example, in ipip mode, the packet length increases by 20 bytes.

Monitoring side:

```bash
# Set capture rules
iptables_debug_tool.sh --white --by-length --set
# Monitor logs
iptables_debug_tool.sh --white --by-length --show
# Clear capture rules
iptables_debug_tool.sh --white --by-length --clear
```

On the sender side:

```bash
# Send packets
hping3 -c 1 --syn --destport 32028 --data 5 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --data 5 10.106.121.108 -j
```

### Based on data content

On the monitoring side:

```bash
# Set capture rules
iptables_debug_tool.sh --white --by-content --set
# Monitor logs
iptables_debug_tool.sh --white --by-content --show
# Clear capture rules
iptables_debug_tool.sh --white --by-content --clear
```

Sender side:

```bash
# Generate data file
echo hello > data.txt

# hping3 used for testing rules without establishing a connection
# Using hping3 with a fixed source port for access, 23130(0x5a5a), --syn for SYN packets, --data for data length, --file for data file
# After establishing a connection, continuous data can be sent, but some logs may not be triggered again
hping3 -c 1 --syn --destport 32028 --baseport 23130 --data 5 --file data.txt 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --baseport 23130 --data 5 --file data.txt 10.106.121.108 -j

# In a k8s cluster, load balancing is based on source ports. Using a fixed source port will always access the same pod
# When testing the cluster, use a random source port for access
hping3 -c 1 --syn --destport 32028 --data 5 --file data.txt 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --data 5 --file data.txt 10.106.121.108 -j

# nc used for testing rules after establishing a connection
# Use nc for access, there might be a nat table omission, follow the sequence: 1. Start nc, 2. Clear connTRACE, 3. Start logging
# Using echo hello | nc 10.106.121.108 32028 -p 23130 might omit the nat table logs
# Also, there might be issues with k8s cluster load balancing, change source ports as needed
nc 10.106.121.108 32028 -p 23130
```

## Blacklist Mode

Blacklist mode requires collecting logs of inactive connections for a period and then adding the traffic from these logs to the ignore list. This ensures the purity of logs during operations.

**Avoid collecting during busy business hours as it might lead to large logs and potentially impact business.**

### Collection Mode

```bash
# Collect ignore list
./iptables_debug_tool.sh --black --collect 3 > ignore_list
# Create ignore rules
./iptables_debug_tool.sh --black --parse ignore_list > rule_list
# Apply ignore rules
./iptables_debug_tool.sh --black --apply rule_list
# Repeat the above steps until there's no more irrelevant traffic in the logs
... ...
# Collect logs from all chains
./iptables_debug_tool.sh --black --apply --full
# Monitor
./iptables_debug_tool.sh --black --show
# Clear
./iptables_debug_tool.sh --black --clear
```

### Default Rule Mode (for k8s clusters)

```bash
# Set calico rules to append mode
cat <<EOF | kubectl apply -f -
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: default
spec:
  bpfLogLevel: ""
  floatingIPs: Disabled
  healthPort: 9099
  logSeverityScreen: Info
  reportingInterval: 0s
  chainInsertMode: Append
EOF
```

```bash
# Apply default ignore rules
./iptables_debug_tool.sh --black --apply-default 10.106.121.47
# Collect logs from all chains
./iptables_debug_tool.sh --black --apply --full
# Monitor
./iptables_debug_tool.sh --black --show
# Clear
./iptables_debug_tool.sh --black --clear
```

## Using Images

- https://hub.docker.com/r/venilnoronha/tcp-echo-server
  - `docker pull venilnoronha/tcp-echo-server:latest`
- https://hub.docker.com/r/utkudarilmaz/hping3
  - `docker pull utkudarilmaz/hping3:latest`
- https://hub.docker.com/r/containous/whoami
  - `docker pull containous/whoami:latest`
- https://hub.docker.com/r/jqknono/simple_echo_server
  - `docker pull jqknono/simple_echo_server:latest`

## Docker Image Usage

- Listen to ports and echo the requests.
- Support TCP & UDP
- Support IPv4 & IPv6

`docker run --rm -it --name simple_echo_server -p 8080:55580/tcp -p 8081:55581/udp jqknono/simple_echo_server:latest`

`nc :: 8080`

`nc -u :: 8081`
