#!/bin/bash

export IS_LIGHT_TRAFFI=0
export TOOL_PREFIX="TRACE"
export SHOW_EXISTING_RULES=0

current_ip=$(hostname -I | awk '{print $1}')

function red() {
    echo -e "\n\033[31m$1\033[0m\n"
}

function green() {
    echo -e "\033[32m$1\033[0m"
}

function yellow() {
    echo -e "\033[33m$1\033[0m"
}

function usage() {
    yellow "Usage: $0 {--black  { --apply-default  <k8s_master_node_ip> | --collect <last_seconds> | --parse <ignore_list> | --apply <rule_list> | --show | --clear } [ --full ] }"
    yellow "Usage: $0 {--white  { --by-content | --by-length } { --set <arg> | --show | --clear } }"
    echo ""
    yellow "--black: blacklist mode"
    yellow "  --apply-default: apply default rules for k8s"
    green "  e.g.: $0 --black --apply-default <k8s_master_node_ip>"
    echo ""
    yellow "  --collect: log ignore connections and last for <last_seconds> seconds"
    yellow "  Could cause system stuck, use with caution. 3 seconds is recommended."
    green "  e.g.: $0 --black --collect 3 > ignore_list"
    echo ""
    yellow "  --parse: generate iptables command"
    green "  e.g.: $0 --black --parse ignore_list > rule_list"
    echo ""
    yellow "  --apply: apply iptables command"
    green "  e.g.: $0 --black --apply rule_list"
    echo ""
    yellow "  The 3 steps above may need to run several times to ignore all connections."
    green "  $0 --black --collect 3 > ignore_list"
    green "  $0 --black --parse ignore_list > rule_list"
    green "  $0 --black --apply rule_list"
    red "  [Attention] --full may cause system stuck. And it could log the full packet path."
    yellow "  Full and DANGEROUS mode:"
    green "  $0 --black --collect 1 --full > ignore_list"
    green "  $0 --black --parse ignore_list > rule_list"
    green "  $0 --black --apply rule_list"
    echo ""
    yellow "  RUN AT LAST, AFTER ALL OTHERS FINISHED."
    red "  This will log packet passing through the 4 chains and 5 tables, and may cause system stuck."
    green "  $0 --black --apply --full"
    echo ""
    yellow "  --show: show log"
    green "  e.g.: $0 --black --show"
    echo ""
    yellow "  --clear: clear log rules"
    green "  e.g.: $0 --black --clear"
    echo ""
    yellow "--white: whitelist mode"
    yellow "  --by-content: whitelist mode by packet content"
    yellow "  --by-length: whitelist mode by packet length"
    red "  By length is simple, but may lost log in some scenarios, like tunnel, which packet length is not fixed."
    yellow "  --set: set whitelist rules"
    green "  e.g.: $0 --white --by-content --set <length>"
    green "  e.g.: $0 --white --by-length --set <content>"
    echo ""
    yellow "  --show: show whitelist rules"
    green "  e.g.: $0 --white --show"
    echo ""
    yellow "  --clear: clear whitelist rules"
    green "  e.g.: $0 --white --clear"
    echo ""

    exit 1
}

function get_iptables_cmd() {
    log_line=$1
    # Extracting parameters from the log line using grep
    in_param=$(echo "$log_line" | grep -oP '(?<=IN=)[^ ]*')
    out_param=$(echo "$log_line" | grep -oP '(?<=OUT=)[^ ]*')
    src_param=$(echo "$log_line" | grep -oP '(?<=SRC=)[^ ]*')
    dst_param=$(echo "$log_line" | grep -oP '(?<=DST=)[^ ]*')
    spt_param=$(echo "$log_line" | grep -oP '(?<=SPT=)[^ ]*')
    dpt_param=$(echo "$log_line" | grep -oP '(?<=DPT=)[^ ]*')
    proto_param=$(echo "$log_line" | grep -oP '(?<=PROTO=)[^ ]*')

    # Extracting table name
    table_name=$(echo "$log_line" | awk '{split($0,a,"[][]"); print a[4]}')

    # Extracting chain name
    chain_name=$(echo "$log_line" | awk '{split($0,a,"[][]"); print a[6]}')

    # Create iptables rule to block the specific traffic
    # iptables -t "$table" -A "$chain" -o "$out_param" -s "$src_param" -d "$dst_param" -p tcp --sport "$spt_param" --dport "$dpt_param" -j DROP
    # fill the param if not null
    null_cnt=0
    command="iptables -t $table_name -A TRACE_PKT_$chain_name"
    if [ -n "$in_param" ]; then
        command="$command -i $in_param"
    else
        null_cnt=$((null_cnt + 1))
    fi

    if [ -n "$out_param" ]; then
        command="$command -o $out_param"
    else
        null_cnt=$((null_cnt + 1))
    fi

    if [ -n "$src_param" ]; then
        command="$command -s $src_param"
    else
        null_cnt=$((null_cnt + 1))
    fi

    if [ -n "$dst_param" ]; then
        command="$command -d $dst_param"
    else
        null_cnt=$((null_cnt + 1))
    fi

    proto_flag=0
    dpt_flag=0
    spt_flag=0
    if [ -n "$proto_param" ]; then
        if [ $proto_param == "TCP" ]; then
            proto_flag=1
        elif [ $proto_param == "UDP" ]; then
            proto_flag=2
        fi
    else
        null_cnt=$((null_cnt + 1))
    fi

    if [ -n "$spt_param" ]; then
        # add if spt_param is in range 0-9999, or 30000-32767(k8s service port range)
        if [ $spt_param -ge 0 -a $spt_param -le 9999 ] || [ $spt_param -ge 30000 -a $spt_param -le 32767 ]; then
            spt_flag=1
        fi
    fi

    if [ -n "$dpt_param" ]; then
        # add if dpt_param is in range 0-9999, or 30000-32767(k8s service port range)
        if [ $dpt_param -ge 0 -a $dpt_param -le 9999 ] || [ $dpt_param -ge 30000 -a $dpt_param -le 32767 ]; then
            dpt_flag=1
        fi
    fi

    # if proto_flag not 0
    if [ ! $proto_flag -eq 0 ]; then
        if [ $spt_flag -eq 1 -o $dpt_flag -eq 1 ]; then
            if [ $proto_flag -eq 1 ]; then
                command="$command \t -p tcp"
            elif [ $proto_flag -eq 2 ]; then
                command="$command \t -p udp"
            fi

            if [ $spt_flag -eq 1 ]; then
                command="$command --sport $spt_param"
            fi
            if [ $dpt_flag -eq 1 ]; then
                command="$command --dport $dpt_param"
            fi
        fi
    fi

    command="$command \t -j RETURN"

    if [ ! $null_cnt -eq 6 ]; then
        echo -e "$command"
    fi
}

function black_generate_iptables_cmd() {
    # create a temp file to store iptables command

    file=$1

    # if file not exist, output usage
    if [ ! -f "$file" ]; then
        red "[ERROR]File $file not exist"
        usage
    fi

    # new iptables_cmd.txt if not exist, clear it if exist
    if [ ! -f "temp_iptables_cmd.txt" ]; then
        touch temp_iptables_cmd.txt
    else
        >temp_iptables_cmd.txt
    fi

    # read file line by line
    while read line; do
        # output to stdout
        get_iptables_cmd "$line" >>temp_iptables_cmd.txt
    done <"$file"

    # output to stdout
    sort temp_iptables_cmd.txt -u

    # remove temp file
    rm temp_iptables_cmd.txt
}

function black_create_log_chain() {
    # iptables -t mangle -L TRACE_PKT_PREROUTING -n >/dev/null 2>&1 || iptables -t mangle -N TRACE_PKT_PREROUTING
    iptables -t mangle -N TRACE_PKT_PREROUTING
    iptables -t mangle -N TRACE_PKT_INPUT
    iptables -t mangle -N TRACE_PKT_FORWARD
    iptables -t mangle -N TRACE_PKT_OUTPUT
    iptables -t mangle -N TRACE_PKT_POSTROUTING
    iptables -t filter -N TRACE_PKT_INPUT
    iptables -t filter -N TRACE_PKT_FORWARD
    iptables -t filter -N TRACE_PKT_OUTPUT
    iptables -t nat -N TRACE_PKT_PREROUTING
    iptables -t nat -N TRACE_PKT_INPUT
    iptables -t nat -N TRACE_PKT_OUTPUT
    iptables -t nat -N TRACE_PKT_POSTROUTING

    iptables -t mangle -D PREROUTING -j TRACE_PKT_PREROUTING
    iptables -t mangle -D INPUT -j TRACE_PKT_INPUT
    iptables -t mangle -D FORWARD -j TRACE_PKT_FORWARD
    iptables -t mangle -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -t mangle -D POSTROUTING -j TRACE_PKT_POSTROUTING
    iptables -t mangle -I PREROUTING -j TRACE_PKT_PREROUTING
    iptables -t mangle -I INPUT -j TRACE_PKT_INPUT
    iptables -t mangle -I FORWARD -j TRACE_PKT_FORWARD
    iptables -t mangle -I OUTPUT -j TRACE_PKT_OUTPUT
    iptables -t mangle -I POSTROUTING -j TRACE_PKT_POSTROUTING

    iptables -t filter -D INPUT -j TRACE_PKT_INPUT
    iptables -t filter -D FORWARD -j TRACE_PKT_FORWARD
    iptables -t filter -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -t filter -I INPUT -j TRACE_PKT_INPUT
    iptables -t filter -I FORWARD -j TRACE_PKT_FORWARD
    iptables -t filter -I OUTPUT -j TRACE_PKT_OUTPUT

    iptables -t nat -D PREROUTING -j TRACE_PKT_PREROUTING
    iptables -t nat -D INPUT -j TRACE_PKT_INPUT
    iptables -t nat -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -t nat -D POSTROUTING -j TRACE_PKT_POSTROUTING
    iptables -t nat -I PREROUTING -j TRACE_PKT_PREROUTING
    iptables -t nat -I INPUT -j TRACE_PKT_INPUT
    iptables -t nat -I OUTPUT -j TRACE_PKT_OUTPUT
    iptables -t nat -I POSTROUTING -j TRACE_PKT_POSTROUTING
}

# Attention: this function could cause system stuck
function black_create_log_rules() {
    iptables -t mangle -A TRACE_PKT_PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -t mangle -A TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -t mangle -A TRACE_PKT_FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -t mangle -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -t mangle -A TRACE_PKT_POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"

    if [ $IS_LIGHT_TRAFFIC -eq 1 ]; then
        iptables -t filter -A TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
        iptables -t filter -A TRACE_PKT_FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
        iptables -t filter -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"
        iptables -t nat -A TRACE_PKT_PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
        iptables -t nat -A TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
        iptables -t nat -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
        iptables -t nat -A TRACE_PKT_POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
    fi
}

function black_del_log_rules() {
    iptables -t mangle -D TRACE_PKT_PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -t mangle -D TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -t mangle -D TRACE_PKT_FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -t mangle -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -t mangle -D TRACE_PKT_POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"

    iptables -t filter -D TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
    iptables -t filter -D TRACE_PKT_FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
    iptables -t filter -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"

    iptables -t nat -D TRACE_PKT_PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
    iptables -t nat -D TRACE_PKT_INPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
    iptables -t nat -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
    iptables -t nat -D TRACE_PKT_POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
}

# create log rules for seconds to avoid system stuck
function black_create_log_rules_for_seconds() {
    if [ $# -lt 1 ]; then
        red "[ERROR]last seconds not specified"
        usage
    fi

    last_seconds=$1
    black_create_log_chain

    # Start logging
    black_create_log_rules

    # Flush conntrack table
    conntrack -F conntrack
    sleep "$last_seconds"

    # Stop logging
    black_del_log_rules

    end=$(date "+%Y-%m-%d %H:%M:%S")
    start=$(date -d "$current_time - $last_seconds seconds" "+%Y-%m-%d %H:%M:%S")
    # grep TRACE, remove ID=[0-9]+, remove WINDOW=[0-9]+, remove LEN=[0-9]+, remove ACK PSH SYN FIN,
    # then sort -u
    journalctl --since "$start" --until "$end" | grep TRACE | sed -r 's/ID=[0-9]+//g' | sed -r 's/WINDOW=[0-9]+ //g' | sed -r 's/LEN=[0-9]+ //g' | sed -r 's/ACK //g' | sed -r 's/PSH //g' | sed -r 's/SYN //g' | sed -r 's/FIN //g' | sort -u
}

function black_apply_default_rule() {
    if [ $# -lt 1 ]; then
        red "[ERROR]master node ip not specified"
        usage
    fi

    black_create_log_chain

    # master node
    master_node_ip=$1
    iptables -t mangle -A TRACE_PKT_PREROUTING -s $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -s $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -s $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -s $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -s $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -s $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -s $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -s $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -s $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -s $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -s $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -s $master_node_ip -j RETURN
    # master node
    iptables -t mangle -A TRACE_PKT_PREROUTING -d $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -d $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -d $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -d $master_node_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -d $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -d $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -d $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -d $master_node_ip -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -d $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -d $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -d $master_node_ip -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -d $master_node_ip -j RETURN

    # broadcast
    broadcast_ip=${master_node_ip%.*}.255
    iptables -t mangle -A TRACE_PKT_PREROUTING -s $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -s $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -s $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -s $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -s $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -s $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -s $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -s $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -s $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -s $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -s $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -s $broadcast_ip -j RETURN
    # broadcast
    iptables -t mangle -A TRACE_PKT_PREROUTING -d $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -d $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -d $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -d $broadcast_ip -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -d $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -d $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -d $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -d $broadcast_ip -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -d $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -d $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -d $broadcast_ip -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -d $master_node_ip -j RETURN

    # tcp ports
    iptables -t mangle -A TRACE_PKT_PREROUTING -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -p tcp -m multiport --dports 22,137,138,179,443,5443,5473,6443 -j RETURN
    # tcp ports
    iptables -t mangle -A TRACE_PKT_PREROUTING -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -p tcp -m multiport --sports 22,137,138,179,443,5443,5473,6443 -j RETURN

    # udp ports
    iptables -t mangle -A TRACE_PKT_PREROUTING -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -p udp -m multiport --dports 53,123,137,138,1900 -j RETURN
    # udp ports
    iptables -t mangle -A TRACE_PKT_PREROUTING -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -p udp -m multiport --sports 53,123,137,138,1900 -j RETURN

    # localhost: 127.0.0.1
    iptables -t mangle -A TRACE_PKT_PREROUTING -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -s 127.0.0.1 -d 127.0.0.1 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -s 127.0.0.1 -d 127.0.0.1 -j RETURN

    # loopback: 224.0.0.1/4
    iptables -t mangle -A TRACE_PKT_PREROUTING -s 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -s 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -s 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -s 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -s 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -s 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -s 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -s 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -s 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -s 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -s 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -s 224.0.0.1/4 -j RETURN
    # loopback: 224.0.0.1/4
    iptables -t mangle -A TRACE_PKT_PREROUTING -d 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_INPUT -d 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_FORWARD -d 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_OUTPUT -d 224.0.0.1/4 -j RETURN
    iptables -t mangle -A TRACE_PKT_POSTROUTING -d 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_PREROUTING -d 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_INPUT -d 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_OUTPUT -d 224.0.0.1/4 -j RETURN
    iptables -t nat -A TRACE_PKT_POSTROUTING -d 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_INPUT -d 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_FORWARD -d 224.0.0.1/4 -j RETURN
    iptables -t filter -A TRACE_PKT_OUTPUT -d 224.0.0.1/4 -j RETURN
}

function black_clear_log_rules() {
    iptables -w -t mangle -D PREROUTING -j TRACE_PKT_PREROUTING
    iptables -w -t mangle -F TRACE_PKT_PREROUTING
    iptables -w -t mangle -X TRACE_PKT_PREROUTING
    iptables -w -t mangle -D INPUT -j TRACE_PKT_INPUT
    iptables -w -t mangle -F TRACE_PKT_INPUT
    iptables -w -t mangle -X TRACE_PKT_INPUT
    iptables -w -t mangle -D FORWARD -j TRACE_PKT_FORWARD
    iptables -w -t mangle -F TRACE_PKT_FORWARD
    iptables -w -t mangle -X TRACE_PKT_FORWARD
    iptables -w -t mangle -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -w -t mangle -F TRACE_PKT_OUTPUT
    iptables -w -t mangle -X TRACE_PKT_OUTPUT
    iptables -w -t mangle -D POSTROUTING -j TRACE_PKT_POSTROUTING
    iptables -w -t mangle -F TRACE_PKT_POSTROUTING
    iptables -w -t mangle -X TRACE_PKT_POSTROUTING
    iptables -w -t filter -D INPUT -j TRACE_PKT_INPUT
    iptables -w -t filter -F TRACE_PKT_INPUT
    iptables -w -t filter -X TRACE_PKT_INPUT
    iptables -w -t filter -D FORWARD -j TRACE_PKT_FORWARD
    iptables -w -t filter -F TRACE_PKT_FORWARD
    iptables -w -t filter -X TRACE_PKT_FORWARD
    iptables -w -t filter -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -w -t filter -F TRACE_PKT_OUTPUT
    iptables -w -t filter -X TRACE_PKT_OUTPUT
    iptables -w -t nat -D PREROUTING -j TRACE_PKT_PREROUTING
    iptables -w -t nat -F TRACE_PKT_PREROUTING
    iptables -w -t nat -X TRACE_PKT_PREROUTING
    iptables -w -t nat -D INPUT -j TRACE_PKT_INPUT
    iptables -w -t nat -F TRACE_PKT_INPUT
    iptables -w -t nat -X TRACE_PKT_INPUT
    iptables -w -t nat -D OUTPUT -j TRACE_PKT_OUTPUT
    iptables -w -t nat -F TRACE_PKT_OUTPUT
    iptables -w -t nat -X TRACE_PKT_OUTPUT
    iptables -w -t nat -D POSTROUTING -j TRACE_PKT_POSTROUTING
    iptables -w -t nat -F TRACE_PKT_POSTROUTING
    iptables -w -t nat -X TRACE_PKT_POSTROUTING
}

function white_len_set_rule() {
    if [ $# -lt 1 ]; then
        red "[ERROR]<lenght> not specified"
        exit 1
    else
        len=$1
    fi
    yellow "set len: $len"

    iptables -t mangle -I PREROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -t nat -I PREROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
    iptables -t mangle -I INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -t nat -I INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
    iptables -t filter -I INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
    iptables -t mangle -I FORWARD -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -t filter -I FORWARD -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
    iptables -t mangle -I OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -t nat -I OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
    iptables -t filter -I OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"
    iptables -t mangle -I POSTROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"
    iptables -t nat -I POSTROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
}

function white_len_clear_rule() {
    len=$(iptables-save | grep -E "FORWARD -m length --length [0-9]+ -j LOG --log-prefix" | awk 'NR==1 {print $6}')
    if [ -z "$len" ]; then
        return
    fi
    yellow "clear len: $len"

    iptables -w -t mangle -D PREROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -w -t nat -D PREROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
    iptables -w -t mangle -D INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -w -t nat -D INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
    iptables -w -t filter -D INPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
    iptables -w -t mangle -D FORWARD -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -w -t filter -D FORWARD -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
    iptables -w -t mangle -D OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -w -t nat -D OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
    iptables -w -t filter -D OUTPUT -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"
    iptables -w -t mangle -D POSTROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"
    iptables -w -t nat -D POSTROUTING -m length --length $len -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
}

function black_show() {
    conntrack -F conntrack
    journalctl -f | grep TRACE
}

function white_show() {
    conntrack -F conntrack
    journalctl -f | grep TRACE
}

function white_content_set_rule() {
    if [ $# -lt 1 ]; then
        red "[ERROR]<content> not specified"
        exit 1
    else
        content=$1
    fi
    yellow "set content: $content"

    iptables -m string --string $content --algo bm -t mangle -I PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -m string --string $content --algo bm -t nat -I PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
    iptables -m string --string $content --algo bm -t mangle -I INPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -m string --string $content --algo bm -t nat -I INPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
    iptables -m string --string $content --algo bm -t filter -I INPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
    iptables -m string --string $content --algo bm -t mangle -I FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -m string --string $content --algo bm -t filter -I FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
    iptables -m string --string $content --algo bm -t mangle -I OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -m string --string $content --algo bm -t nat -I OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
    iptables -m string --string $content --algo bm -t filter -I OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"
    iptables -m string --string $content --algo bm -t mangle -I POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"
    iptables -m string --string $content --algo bm -t nat -I POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
}

function white_content_clear_rule() {
    content=$(iptables-save | grep -E "FORWARD -m string --string \"\S+\" --algo bm --to 65535 -j LOG --log-prefix" | awk 'NR==1 {print $6}')
    content=${content//\"/}
    if [ -z "$content" ]; then
        return
    fi
    yellow "clear content: $content"

    iptables -w -m string --string $content --algo bm -t mangle -D PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][PREROUTING ]:"
    iptables -w -m string --string $content --algo bm -t nat -D PREROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][PREROUTING ]:"
    iptables -w -m string --string $content --algo bm -t mangle -D INPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][INPUT      ]:"
    iptables -w -m string --string $content --algo bm -t nat -D INPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][INPUT      ]:"
    iptables -w -m string --string $content --algo bm -t filter -D INPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][INPUT      ]:"
    iptables -w -m string --string $content --algo bm -t mangle -D FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][mangle][FORWARD    ]:"
    iptables -w -m string --string $content --algo bm -t filter -D FORWARD -j LOG --log-prefix "[$TOOL_PREFIX][filter][FORWARD    ]:"
    iptables -w -m string --string $content --algo bm -t mangle -D OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][mangle][OUTPUT     ]:"
    iptables -w -m string --string $content --algo bm -t nat -D OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][OUTPUT     ]:"
    iptables -w -m string --string $content --algo bm -t filter -D OUTPUT -j LOG --log-prefix "[$TOOL_PREFIX][filter][OUTPUT     ]:"
    iptables -w -m string --string $content --algo bm -t mangle -D POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][mangle][POSTROUTING]:"
    iptables -w -m string --string $content --algo bm -t nat -D POSTROUTING -j LOG --log-prefix "[$TOOL_PREFIX][nat   ][POSTROUTING]:"
}

function black_apply_iptables_cmd() {
    if [ $# -lt 1 ]; then
        red "[ERROR]No file specified."
        usage
    fi

    file=$1
    if [ $1 == "--full" ]; then
        IS_LIGHT_TRAFFIC=1
        black_del_log_rules
        black_create_log_rules
        exit 0
    fi

    # if file not exist, output usage
    if [ ! -f "$file" ]; then
        red "[ERROR]File $file not exist."
        usage
    fi

    black_del_log_rules

    # read file line by line
    while read line; do
        eval "$line"
    done <"$file"

    black_create_log_rules
}

function white_len_usage() {
    if [ $# -lt 1 ]; then
        len=30
    else
        len=$1
    fi
    valid_len=$(($len - 29))
    content=$(tr -dc '5a' </dev/urandom | head -c $valid_len)
    red "[Whitelist mode by length]"
    yellow "The receiver command:"
    green "nc -kluvp 32028"
    echo ""
    yellow "The sender command:"
    yellow "Avoid established connection(by packet length):"
    green "hping3 -c 1 --syn --destport 32028 --data 5 $current_ip -j"
    echo ""
    yellow "Established connection:"
    green "nc -u $current_ip 32028 -p 23130"
    green "$content"
    echo ""
}

function white_content_usage() {
    if [ $# -lt 1 ]; then
        content="hello"
    else
        content=$1
    fi
    red "[Whitelist mode by content]"
    yellow "The receiver command:"
    green "nc -kluvp 32028"
    echo ""
    yellow "The sender command:"
    yellow "Create data file:"
    green "echo $content > data.txt"
    echo ""
    yellow "Avoid established connection(by packet content):"
    green "hping3 -c 1 --syn --destport 32028 --data 5 --file data.txt $current_ip -j"
    echo ""
    yellow "Established connection:"
    green "nc -u $current_ip 32028 -p 23130"
    green "$content"
    echo ""
}

function main() {
    # if no file specified, output usage
    if [ $# -lt 1 ]; then
        red "[ERROR]No mode specified."
        usage
    fi

    # get params
    case $1 in
    -h | --help)
        usage
        ;;
    --black)
        shift
        case $1 in
        --collect)
            shift
            if [ $# -gt 1 ]; then
                if [ $2 == "--full" ]; then
                    IS_LIGHT_TRAFFIC=1
                fi
            fi
            black_create_log_rules_for_seconds $1
            ;;
        --parse)
            shift
            black_generate_iptables_cmd $1
            ;;
        --apply)
            shift
            if [ $# -gt 1 ]; then
                if [ $2 == "--full" ]; then
                    IS_LIGHT_TRAFFIC=1
                fi
            fi
            black_apply_iptables_cmd $1
            ;;
        --apply-default)
            shift
            black_apply_default_rule $1
            ;;
        --show)
            black_show
            ;;
        --clear)
            black_clear_log_rules
            ;;
        *)
            red "[ERROR]No action match."
            usage
            ;;
        esac
        ;;

    --white)
        shift
        case $1 in
        --by-length)
            shift
            case $1 in
            --set)
                if [ $# -lt 2 ]; then
                    red "[ERROR]<length> not specified"
                    exit 1
                fi
                white_len_clear_rule
                white_len_set_rule $2
                white_len_usage $2
                red "Run the following command to show log:"
                # green "$0 --white --by-length --show"
                green "$0 --white --show"
                echo ""
                ;;
            --show)
                white_len_usage
                red "Run the following command before show log:"
                green "$0 --white --by-length --set"
                echo ""
                white_show
                ;;
            --clear)
                white_len_clear_rule
                ;;
            *)
                red "[ERROR]No action match."
                usage
                ;;
            esac
            ;;
        --by-content)
            shift
            case $1 in
            --set)
                if [ $# -lt 2 ]; then
                    red "[ERROR]<content> not specified"
                    exit 1
                fi
                white_content_clear_rule
                white_content_set_rule $2
                white_content_usage $2
                red "Run the following command to show log:"
                # green "$0 --white --by-content --show"
                green "$0 --white --show"
                echo ""
                ;;
            --show)
                white_content_usage
                red "Run the following command before show log:"
                green "$0 --white --by-content --set"
                echo ""
                white_show
                ;;
            --clear)
                white_content_clear_rule
                ;;
            *)
                red "[ERROR]No action match."
                usage
                ;;
            esac
            ;;
        --show)
            white_show
            ;;
        --clear)
            white_len_clear_rule
            white_content_clear_rule
            ;;
        *)
            red "[ERROR]No mode match."
            usage
            ;;
        esac
        ;;
    *)
        red "[ERROR]No mode match."
        usage
        ;;
    esac
}

# check if conntrack is installed
if ! command -v conntrack &>/dev/null; then
    red "[ERROR]conntrack is not installed"
    green "Please install conntrack : sudo apt install conntrack"
    exit 1
fi

# show existing rules
if [ $SHOW_EXISTING_RULES -eq 1 ]; then
    existed=$(iptables-save | grep "\[$TOOL_PREFIX\]")
    if [ -z "$existed" ]; then
        echo ""
    else
        yellow "Existing rules:"
        echo ""
        green "$existed"
    fi
fi

main "$@"
