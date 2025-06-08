#!/usr/bin/env bash

bin="~/go/bin/dns-tools"
db="tldr.sqlite3"
GITHUB_MAX_SIZE=99614720
scan() {
	eval "$bin" -db "$db" $*
}

multi_scan() {
	for flag in $*; do
		scan $flag
	done
}

get_ns_ips() {
	multi_scan -{net,rr}_ns -{net,rr}_ip -zone_ns_ip
}

prework() {
	# create dummy db
	scan -rr_ip
	# add root zone
	sqlite3 "$db" "INSERT OR IGNORE INTO name (name, is_zone) VALUES ('.', TRUE)"
	# fetch and parse root nameserver records
	get_ns_ips
	# axfr root nameservers
	scan -direct_conns -v6 -axfr
	# get TLD nameserver info
	get_ns_ips

	# download PSL
	wget https://raw.githubusercontent.com/publicsuffix/list/refs/heads/main/public_suffix_list.dat || exit 1
	# convert to idna lol
	sed '/^\/\//d;/^$/d;s/^\*\.//;s/^!//' public_suffix_list.dat | python3 -c 'print("\n".join(x.encode("idna").decode() for x in __import__("sys").stdin.read().splitlines()))' > psl.txt
	# add entries
	scan -parse_lists psl.txt
	# idk, check for zones
	for i in {1..5}; do
		scan -validate
		scan -parent_map
		scan -maybe_zone
	done

	# idk
	for i in {1..3}; do
		get_ns_ips
	done
}

axfr() {
	# axfr TLD nameservers
	scan -direct_conns -v6 -axfr
}

zonefiles() {
	sqlite3 "$db" 'SELECT DISTINCT zone.name FROM zone_ns_ip INNER JOIN name AS zone ON zone_ns_ip.zone_id=zone.id WHERE zone_ns_ip.axfrable=TRUE' | while read zone; do
		if [[ $zone = '.' ]]; then
			path_name='root'
		else
			path_name="${zone%.}"
		fi

		dir="archives/${path_name}/"
		filepath="${dir}/${path_name}.zone"
		mkdir -p "$dir"
		sqlite3 "$db" "SELECT DISTINCT rr_value.value FROM zone2rr INNER JOIN zone_ns_ip ON zone2rr.zone_id=zone_ns_ip.zone_id INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id INNER JOIN name AS zone ON zone2rr.zone_id=zone.id WHERE zone.name='${zone}'" | sort -u | ldns-read-zone -zsne TXT -e ZONEMD > ${filepath}.tmp

		filesize=$(wc -c ${filepath}.tmp | cut -d' ' -f1)
		if [[ $filesize == 0 ]]; then
			rm ${filepath}.tmp
			continue
		fi
		mv ${filepath}{.tmp,}
		if [[ $filesize > $GITHUB_MAX_SIZE ]]; then
			gzip ${filepath}
		fi
		echo "dumping zone ${zone}"
	done
}

walkable() {
	scan -nsec_map
}

get_walkable() {
	sqlite3 "$db" "SELECT zone.name FROM zone_nsec_state INNER JOIN nsec_state ON zone_nsec_state.nsec_state_id=nsec_state.id INNER JOIN name AS zone ON zone_nsec_state.zone_id=zone.id WHERE nsec_state.name='plain_nsec' ORDER BY zone.name"
}

walk() {
	sqlite3 "$db" "UPDATE name SET nsec_walked=TRUE"
	sqlite3 "$db" "UPDATE name SET nsec_walked=FALSE WHERE name='${1}'"
	scan -zone_walk -num_procs 16
	ldns-read-zone -z <(sqlite3 tldr.sqlite3 "SELECT rr_name.name FROM zone_walk_res INNER JOIN rr_type ON zone_walk_res.rr_type_id=rr_type.id INNER JOIN rr_name ON zone_walk_res.rr_name_id=rr_name.id WHERE rr_type.name='NS'" | grep -v "^${1}$" | sed 's/$/ TXT ""/') | awk '{print $1}' > "walk_lists/${1}list"
}

md_axfr() {
	printf '# List of TLDs & Roots With Zone Transfers Currently Enabled\n\n' > transferable_zones.md

	sqlite3 "$db" 'SELECT zone.name, ip.address FROM zone_ns_ip INNER JOIN name AS zone ON zone_ns_ip.zone_id=zone.id INNER JOIN ip ON zone_ns_ip.ip_id=ip.id WHERE zone_ns_ip.axfrable=TRUE' | while read line; do
		zone=$(echo "$line" | cut -d'|' -f1)
		ip=$(echo "$line" | cut -d'|' -f2)

		# "uninteresting" zones that produce too much flux
		if [[ $zone = . || $zone = arpa. ]]; then
			continue
		fi

		path_name="${zone%.}"

		printf '* `%s` via `%s`: [Click here to view zone data.](archives/%s/%s.zone)\n' "$zone" "$ip" "$path_name" "$path_name" >> transferable_zones.md
	done
}

md_walkable() {
	printf '# List of TLDs & Roots With Walkable NSEC Records\n\n' > walkable_zones.md

	get_walkable | while read zone; do
		printf '* `%s`\n' "$zone" >> walkable_zones.md
	done
}

$*
