BEGIN {
    FS = "[[:space:]]+"
}

FILENAME ~ /in-addr\.arpa\.zone$/ && $4 == "PTR" {
    split($1, labels, ".")
    ip = "192.0.2." labels[1]
    target = tolower($5)
    ptr_count[ip]++
    ptr_targets[ip] = append(ptr_targets[ip], target)
    ptr_ip[target] = ip
    next
}

$4 == "A" && $5 ~ /^192\.168\.253\.[0-9]+$/ {
    name = tolower($1)
    ip = $5
    forward_count[ip]++
    forward_names[ip] = append(forward_names[ip], name)
    forward_ip[name] = ip
}

END {
    for (ip in forward_count) {
        if (!(ip in ptr_count)) {
            missing++
            details[++detail_count] = "MISSING_PTR " ip " forward=" forward_names[ip]
        }
    }

    for (ip in ptr_count) {
        if (ptr_count[ip] > 1) {
            duplicate++
            details[++detail_count] = "MULTIPLE_PTR " ip " ptr=" ptr_targets[ip]
        }
        split(ptr_targets[ip], targets, ",")
        for (i in targets) {
            target = targets[i]
            if (!(target in forward_ip)) {
                stale++
                details[++detail_count] = "PTR_WITHOUT_A " ip " ptr=" target
            } else if (forward_ip[target] != ip) {
                mismatch++
                details[++detail_count] = "PTR_A_MISMATCH " ip " ptr=" target " a=" forward_ip[target]
            }
        }
    }

    print "forward_addresses=" length(forward_count)
    print "reverse_addresses=" length(ptr_count)
    print "missing_ptr=" missing + 0
    print "multiple_ptr=" duplicate + 0
    print "ptr_without_a=" stale + 0
    print "ptr_a_mismatch=" mismatch + 0
    print ""
    for (i = 1; i <= detail_count; i++) print details[i]
}

function append(existing, value) {
    return existing == "" ? value : existing "," value
}
