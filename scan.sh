#!/bin/bash

bin="~/go/bin/dns-tools"
db="tldr.sqlite3"
GITHUB_MAX_SIZE=99614720
scan() {
	eval "$bin" -db "$db" $*
}

main() {
	# create dummy db
	scan -rr_ip
	# add root zone
	sqlite3 "$db" "INSERT OR IGNORE INTO name (name, is_zone) VALUES ('.', TRUE)"
	# get root nameservers
	scan -net_{ns,ip}
	# axfr root nameservers
	scan -direct_conns -v6 -axfr
	# get TLD nameserver info
	scan -{rr,net}_{ns,ip}
	# axfr TLD nameservers
	scan -direct_conns -v6 -axfr

	for zone in $(sqlite3 "$db" 'SELECT DISTINCT zone.name FROM zone2rr INNER JOIN name AS zone ON zone2rr.zone_id=zone.id'); do
		if [[ $zone = '.' ]]; then
			path_name='root'
		else
			path_name="${zone%.}"
		fi

		dir="archives/${path_name}/"
		filepath="${dir}/${path_name}.zone"
		mkdir -p "$dir"
		sqlite3 "$db" "SELECT rr_value.value FROM zone2rr INNER JOIN name AS zone ON zone2rr.zone_id=zone.id INNER JOIN rr_value ON zone2rr.rr_value_id=rr_value.id WHERE zone.name='${zone}'" > ${filepath}.tmp
		ldns-read-zone -zs ${filepath}.tmp > ${filepath}
		rm ${filepath}.tmp

		filesize=$(wc -c ${filepath})
		if [[ $filesize > $GITHUB_MAX_SIZE ]]; then
			gzip ${filepath}
		fi
	done

	printf '# List of TLDs & Roots With Zone Transfers Currently Enabled\n\n' > transferable_zones.md

	for line in $(sqlite3 tldr.sqlite3 'SELECT DISTINCT zone.name, ns.name FROM axfrable_ns INNER JOIN name AS zone ON axfrable_ns.zone_id=zone.id INNER JOIN name_ip ON name_ip.ip_id=axfrable_ns.ip_id INNER JOIN zone_ns ON zone_ns.zone_id=zone.id INNER JOIN name AS ns ON zone_ns.ns_id=ns.id WHERE name_ip.name_id=ns.id ORDER BY zone.name, ns.name'); do
		zone=$(echo "$line" | cut -d'|' -f1)
		ns=$(echo "$line" | cut -d'|' -f2)

		if [[ $zone = '.' ]]; then
			path_name='root'
		else
			path_name="${zone%.}"
		fi

		printf '* `%s` via `%s`: [Click here to view zone data.](archives/%s/%s.zone)\n' "$zone" "$ns" "$path_name" "$path_name" >> transferable_zones.md
	done
}

main
