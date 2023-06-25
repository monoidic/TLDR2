#!/bin/bash

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
	multi_scan -{net,rr}_ns -{net,rr}_ip
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

	# idk
	scan -rr_{ns,ip}
	scan -net_{ns,ip}
	scan -rr_{ns,ip}
}

axfr() {
	# axfr TLD nameservers
	scan -direct_conns -v6 -axfr
}

zonefiles() {
	for zone in $(sqlite3 "$db" 'SELECT DISTINCT zone.name FROM zone2rr INNER JOIN name AS zone ON zone2rr.zone_id=zone.id'); do
		echo "dumping zone ${zone}"
		if [[ $zone = '.' ]]; then
			path_name='root'
		else
			path_name="${zone%.}"
		fi

		dir="archives/${path_name}/"
		filepath="${dir}/${path_name}.zone"
		mkdir -p "$dir"
		sqlite3 "$db" "SELECT rr_value.value FROM zone2rr INNER JOIN axfrable_ns ON zone2rr.zone_id=axfrable_ns.zone_id INNER JOIN name AS zone ON zone2rr.zone_id=zone.id INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id WHERE zone.name='${zone}'" | sort -u | ldns-read-zone -zsne TXT > ${filepath}

		filesize=$(wc -c ${filepath})
		if [[ $filesize > $GITHUB_MAX_SIZE ]]; then
			gzip ${filepath}
		fi
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
	scan -zone_walk -num_procs 16 -tcp
	scan -zone_walk_results
	scan -rr_{ns,ip}
	scan -net_{ns,ip}
	scan -rr_{ns,ip}
	scan -parent_map
	sqlite3 "$db" "SELECT rr_value.value FROM zone2rr INNER JOIN name AS zone ON zone2rr.zone_id=zone.id INNER JOIN name AS parent ON zone.parent_id=parent.id INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id WHERE parent.name='${1}'" | sort -u | ldns-read-zone -zsne TXT > "walks/${1}zone"
}

md_axfr() {
	printf '# List of TLDs & Roots With Zone Transfers Currently Enabled\n\n' > transferable_zones.md

	for line in $(sqlite3 $db 'SELECT DISTINCT zone.name, ns.name FROM axfrable_ns INNER JOIN name AS zone ON axfrable_ns.zone_id=zone.id INNER JOIN name_ip ON name_ip.ip_id=axfrable_ns.ip_id INNER JOIN zone_ns ON zone_ns.zone_id=zone.id INNER JOIN name AS ns ON zone_ns.ns_id=ns.id WHERE name_ip.name_id=ns.id ORDER BY zone.name, ns.name'); do
		zone=$(echo "$line" | cut -d'|' -f1)
		ns=$(echo "$line" | cut -d'|' -f2)

		# "uninteresting" zones that produce too much flux
		if [[ $zone = . || $zone = arpa. ]]; then
			continue
		fi

		path_name="${zone%.}"

		printf '* `%s` via `%s`: [Click here to view zone data.](archives/%s/%s.zone)\n' "$zone" "$ns" "$path_name" "$path_name" >> transferable_zones.md
	done
}

md_walkable() {
	printf '# List of TLDs & Roots With Walkable NSEC Records\n\n' > walkable_zones.md

	for zone in $(get_walkable); do
		printf '* `%s`\n' "$zone" >> walkable_zones.md
	done
}

$*
