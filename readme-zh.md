# IPTABLES DEBUG

抓包日志是一种调试防火墙规则的方式, 但抓包时存在许多无用的包, 有两种方式可以仅取抓指定的包, 一个是白名单模式, 一个是黑名单模式.

- 白名单模式: 仅抓取符合特征的报文, 需要自行构造报文, 通常只需要构造 SYN 报文即可, 但每次测试前注意使用 connTRACE -F 清理已建立连接.
- 黑名单模式: 先采集一段时间的无操作日志, 将日志中的流量加入到日志的忽略名单里, 这样在操作时可以保证日志的纯净性.

**能抓取最完整报文路径的方式是黑名单模式, 但设置较繁琐.**, 按需自行修改脚本`black_apply_default_rule`函数.

本脚本帮助实现这两种方式的抓包.

## 白名单模式

依赖工具:

- hping3:
  - centos: `yum -y install epel-release & yum -y install hping3`
  - ubuntu: `apt-get -y install hping3`

### 基于 data 长度

注意报文在传输过程中长度可能会发生变化, 导致报文路径不完整, 比如在 ipip 模式下, 报文长度会增加 20 字节.

监控端:

```bash
# 设置采集规则
iptables_debug_tool.sh --white --by-length --set
# 监控日志
iptables_debug_tool.sh --white --by-length --show
# 清理采集规则
iptables_debug_tool.sh --white --by-length --clear
```

发送端:

```bash
# 发送报文
hping3 -c 1 --syn --destport 32028 --data 5 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --data 5 10.106.121.108 -j
```

### 基于 data 内容

监控端:

```bash
# 设置采集规则
iptables_debug_tool.sh --white --by-content --set
# 监控日志
iptables_debug_tool.sh --white --by-content --show
# 清理采集规则
iptables_debug_tool.sh --white --by-content --clear
```

发送端:

```bash
# 生成data文件
echo hello > data.txt

# hping3用于测试未创建连接时的规则
# 使用hping3固定源端口进行访问, 23130(0x5a5a), --syn表示SYN报文, --data表示data长度, --file表示data文件
# 建立连接后, 可以持续发送数据, 但部分日志不会再触发
hping3 -c 1 --syn --destport 32028 --baseport 23130 --data 5 --file data.txt 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --baseport 23130 --data 5 --file data.txt 10.106.121.108 -j

# k8s集群根据源端口进行负载均衡, 固定源端口会导致总是访问到同一个pod
# 测试集群时, 请使用随机源端口进行访问
hping3 -c 1 --syn --destport 32028 --data 5 --file data.txt 10.106.121.108 -j
hping3 -c 1 -2    --destport 32028 --data 5 --file data.txt 10.106.121.108 -j

# nc用于测试已创建连接后的规则
# 使用nc进行访问, 可能存在nat表遗漏, 注意按顺序操作, 1. 启动nc, 2. 清理connTRACE, 3. 启动日志
# 直接使用echo hello | nc 10.106.121.108 32028 -p 23130, 会遗漏nat表的日志
# 也存在k8s集群负载均衡失效的可能, 注意更换源端口
nc 10.106.121.108 32028 -p 23130
```

## 黑名单模式

黑名单模式需要先采集一段时间的不关注连接的日志, 然后将日志中的流量加入到日志的忽略名单里, 这样在操作时可以保证日志的纯净性.

**注意避免在业务过于繁忙的时间段采集, 会导致日志过大, 且可能会影响业务**

### 采集模式

```bash
# 采集忽略名单
./iptables_debug_tool.sh --black --collect 3 > ignore_list
# 创建忽略规则
./iptables_debug_tool.sh --black --parse ignore_list > rule_list
# 应用忽略规则
./iptables_debug_tool.sh --black --apply rule_list
# 重复以上步骤, 直到日志中不再有无关流量
... ...
# 采集所有链表的日志
./iptables_debug_tool.sh --black --apply --full
# 监控
./iptables_debug_tool.sh --black --show
# 清空
./iptables_debug_tool.sh --black --clear
```

### 默认规则模式(适用 k8s 集群)

```bash
# 设置calico规则为append模式
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
# 应用默认忽略规则
./iptables_debug_tool.sh --black --apply-default 10.106.121.47
# 采集所有链表的日志
./iptables_debug_tool.sh --black --apply --full
# 监控
./iptables_debug_tool.sh --black --show
# 清空
./iptables_debug_tool.sh --black --clear
```

## 使用镜像

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
