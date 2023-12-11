#!/bin/bash

IS_LIGHT_TRAFFIC=0
export IS_LIGHT_TRAFFIC

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
    yellow "Usage: $0 {--black  { --collect <last_seconds> | --parse <ignore_list> | --apply <rule_list> | --show | --clear } [ --full ] }"
    yellow "Usage: $0 {--white  { --by-content | --by-length } { --set | --show | --clear } }"
    echo ""
    yellow "  --black: black list mode"
    yellow "  --collect: log ignore connections and last for <last_seconds> seconds"
    yellow "  Could cause system stuck, use with caution. 3 seconds is recommended."
    green "  e.g.: $0 --black --collect 3 > ignore_list"
    yellow "  --parse: generate iptables command"
    green "  e.g.: $0 --black --parse ignore_list > rule_list"
    yellow "  --apply: apply iptables command"
    green "  e.g.: $0 --black --apply rule_list"
    yellow "  The 3 steps above may need to run several times to ignore all connections."
    green "  $0 --black --collect 3 > ignore_list"
    green "  $0 --black --parse ignore_list > rule_list"
    green "  $0 --black --apply rule_list"
    red "  [Attention]: --full may cause system stuck. And it could log the full packet path."
    yellow "  Full and DANGEROUS mode:"
    green "  $0 --black --collect 1 --full > ignore_list"
    green "  $0 --black --parse ignore_list > rule_list"
    green "  $0 --black --apply rule_list"
    yellow "  RUN AT LAST, AFTER ALL OTHERS FINISHED."
    green "  This will log packet passing through the 4 chains and 5 tables, and may cause system stuck."
    green "  $0 --black --apply rule_list --full"
    echo ""
    yellow "  --show: show log"
    green "  e.g.: $0 --black --show"
    yellow "  --clear: clear log rules"
    green "  e.g.: $0 --black --clear"
    echo ""
    yellow "  --white: whitelist mode"
    yellow "  --by-content: whitelist mode by packet content"
    yellow "  --by-length: whitelist mode by packet length"
    yellow "  By length is simple, but may lost log in some scenarios, like tunnel, which packet length is not fixed."
    yellow "  --set: set whitelist rules"
    green "  e.g.: $0 --white --by-content --set"
    yellow "  --show: show whitelist rules"
    green "  e.g.: $0 --white --by-content --show"
    yellow "  --clear: clear whitelist rules"
    green "  e.g.: $0 --white --by-content --clear"

    exit 1
}

function get_iptables_cmd() {
    log_line=$1
    # Extracting parameters from the log line using grep
    in_param=$(echo "$log_line" | grep -oP '(?<=IN=)[^ ]*')
    out_param=$(echo "$log_line" | grep -oP '(?<=OUT=)[^ ]*')
    src_param=$(echo "$log_line" | grep -oP '(?<=SRC=)[^ ]*')
    dst_param=$(echo "$log_line" | grep -oP '(?<=DST=)[^ ]*')

    # Extracting table name
    table_name=$(echo "$log_line" | awk '{split($0,a,"[][]"); print a[4]}')

    # Extracting chain name
    chain_name=$(echo "$log_line" | awk '{split($0,a,"[][]"); print a[6]}')

    # Create iptables rule to block the specific traffic
    # iptables -t "$table" -A "$chain" -o "$out_param" -s "$src_param" -d "$dst_param" -j DROP
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

    command="$command -j RETURN"

    if [ ! $null_cnt -eq 5 ]; then
        echo "$command"
    fi
}

function black_generate_iptables_cmd() {
    # create a temp file to store iptables command

    file=$1

    # if file not exist, output usage
    if [ ! -f "$file" ]; then
        echo "file not exist"
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
    sort temp_iptables_cmd.txt | uniq

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
    iptables -t mangle -A TRACE_PKT_PREROUTING -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -t mangle -A TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -t mangle -A TRACE_PKT_FORWARD -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -t mangle -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -t mangle -A TRACE_PKT_POSTROUTING -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"

    if [ $IS_LIGHT_TRAFFIC -eq 1 ]; then
        iptables -t filter -A TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
        iptables -t filter -A TRACE_PKT_FORWARD -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
        iptables -t filter -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"
        iptables -t nat -A TRACE_PKT_PREROUTING -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
        iptables -t nat -A TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
        iptables -t nat -A TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
        iptables -t nat -A TRACE_PKT_POSTROUTING -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
    fi
}

function black_del_log_rules() {
    iptables -t mangle -D TRACE_PKT_PREROUTING -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -t mangle -D TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -t mangle -D TRACE_PKT_FORWARD -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -t mangle -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -t mangle -D TRACE_PKT_POSTROUTING -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"

    iptables -t filter -D TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
    iptables -t filter -D TRACE_PKT_FORWARD -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
    iptables -t filter -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"

    iptables -t nat -D TRACE_PKT_PREROUTING -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
    iptables -t nat -D TRACE_PKT_INPUT -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
    iptables -t nat -D TRACE_PKT_OUTPUT -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
    iptables -t nat -D TRACE_PKT_POSTROUTING -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
}

# create log rules for seconds to avoid system stuck
function black_create_log_rules_for_seconds() {
    if [ $# -lt 1 ]; then
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
    journalctl --since "$start" --until "$end" | grep TRACE | sort | uniq
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
    iptables -t mangle -I PREROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -t nat -I PREROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
    iptables -t mangle -I INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -t nat -I INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
    iptables -t filter -I INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
    iptables -t mangle -I FORWARD -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -t filter -I FORWARD -m length --length 45 -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
    iptables -t mangle -I OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -t nat -I OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
    iptables -t filter -I OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"
    iptables -t mangle -I POSTROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"
    iptables -t nat -I POSTROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
}

function white_len_clear_rule() {
    iptables -w -t mangle -D PREROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -w -t nat -D PREROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
    iptables -w -t mangle -D INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -w -t nat -D INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
    iptables -w -t filter -D INPUT -m length --length 45 -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
    iptables -w -t mangle -D FORWARD -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -w -t filter -D FORWARD -m length --length 45 -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
    iptables -w -t mangle -D OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -w -t nat -D OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
    iptables -w -t filter -D OUTPUT -m length --length 45 -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"
    iptables -w -t mangle -D POSTROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"
    iptables -w -t nat -D POSTROUTING -m length --length 45 -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
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
    iptables -m string --string "hello" --algo bm -t mangle -I PREROUTING -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -m string --string "hello" --algo bm -t nat -I PREROUTING -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
    iptables -m string --string "hello" --algo bm -t mangle -I INPUT -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -m string --string "hello" --algo bm -t nat -I INPUT -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
    iptables -m string --string "hello" --algo bm -t filter -I INPUT -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
    iptables -m string --string "hello" --algo bm -t mangle -I FORWARD -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -m string --string "hello" --algo bm -t filter -I FORWARD -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
    iptables -m string --string "hello" --algo bm -t mangle -I OUTPUT -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -m string --string "hello" --algo bm -t nat -I OUTPUT -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
    iptables -m string --string "hello" --algo bm -t filter -I OUTPUT -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"
    iptables -m string --string "hello" --algo bm -t mangle -I POSTROUTING -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"
    iptables -m string --string "hello" --algo bm -t nat -I POSTROUTING -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
}

function white_content_clear_rule() {
    iptables -w -m string --string "hello" --algo bm -t mangle -D PREROUTING -j LOG --log-prefix "[TRACE][mangle][PREROUTING ]:"
    iptables -w -m string --string "hello" --algo bm -t nat -D PREROUTING -j LOG --log-prefix "[TRACE][nat   ][PREROUTING ]:"
    iptables -w -m string --string "hello" --algo bm -t mangle -D INPUT -j LOG --log-prefix "[TRACE][mangle][INPUT      ]:"
    iptables -w -m string --string "hello" --algo bm -t nat -D INPUT -j LOG --log-prefix "[TRACE][nat   ][INPUT      ]:"
    iptables -w -m string --string "hello" --algo bm -t filter -D INPUT -j LOG --log-prefix "[TRACE][filter][INPUT      ]:"
    iptables -w -m string --string "hello" --algo bm -t mangle -D FORWARD -j LOG --log-prefix "[TRACE][mangle][FORWARD    ]:"
    iptables -w -m string --string "hello" --algo bm -t filter -D FORWARD -j LOG --log-prefix "[TRACE][filter][FORWARD    ]:"
    iptables -w -m string --string "hello" --algo bm -t mangle -D OUTPUT -j LOG --log-prefix "[TRACE][mangle][OUTPUT     ]:"
    iptables -w -m string --string "hello" --algo bm -t nat -D OUTPUT -j LOG --log-prefix "[TRACE][nat   ][OUTPUT     ]:"
    iptables -w -m string --string "hello" --algo bm -t filter -D OUTPUT -j LOG --log-prefix "[TRACE][filter][OUTPUT     ]:"
    iptables -w -m string --string "hello" --algo bm -t mangle -D POSTROUTING -j LOG --log-prefix "[TRACE][mangle][POSTROUTING]:"
    iptables -w -m string --string "hello" --algo bm -t nat -D POSTROUTING -j LOG --log-prefix "[TRACE][nat   ][POSTROUTING]:"
}

function black_apply_iptables_cmd() {
    if [ $# -lt 1 ]; then
        usage
    fi

    file=$1
    # if file not exist, output usage
    if [ ! -f "$file" ]; then
        echo "file not exist"
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
    red "[Whitelist mode by length]"
    yellow "The sender command, e.g.:"
    yellow "Not established connection(by packet length):"
    green "hping3 -c 1 --syn --destport 32028 --data 5 10.106.121.108 -j"
    yellow "Established connection:"
    green "nc 10.106.121.108 32028 -p 23130"
}

function white_content_usage() {
    red "[Whitelist mode by content]"
    yellow "The sender command, e.g.:"
    yellow "Create data file:"
    green "echo hello > data.txt"
    yellow "Not established connection(by packet content):"
    green "hping3 -c 1 --syn --destport 32028 --data 5 --file data.txt 10.106.121.108 -j"
    yellow "Established connection:"
    green "nc 10.106.121.108 32028 -p 23130"
}

function main() {
    # if no file specified, output usage
    if [ $# -lt 1 ]; then
        usage
    fi

    # get params
    case $1 in
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
                white_len_usage
                red "Run the following command to show log:"
                green "$0 --white --by-length --show"
                white_len_set_rule
                ;;
            --show)
                white_content_usage
                red "Run the following command before show log:"
                green "$0 --white --by-length --set"
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
                white_content_usage
                red "Run the following command to show log:"
                green "$0 --white --by-content --show"
                white_content_set_rule
                ;;
            --show)
                white_content_usage
                red "Run the following command before show log:"
                green "$0 --white --by-content --set"
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
        esac
        ;;
    *)
        red "[ERROR]No mode match."
        usage
        ;;
    esac
}

main "$@"
