BEGIN {
    FS = ","
    OFS = ","
}

NR == 1 {
    print "cell", "engine", "stage", "samples", "min_ns_per_iter", "mean_ns_per_iter", "max_ns_per_iter", "semantic_value", "code_bytes", "data_bytes", "total_mapped_bytes", "instructions", "vector_instructions", "fixture"
    next
}

{
    key = $5 SUBSEP $12 SUBSEP $13
    value = $17 + 0
    if (!(key in count) || value < minimum[key]) {
        minimum[key] = value
    }
    if (!(key in count) || value > maximum[key]) {
        maximum[key] = value
    }
    count[key]++
    sum[key] += value
    semantic[key] = $19
    code[key] = $20
    data[key] = $21
    mapped[key] = $23
    instructions[key] = $25
    vectors[key] = $26
    fixture[key] = $35
}

END {
    for (key in count) {
        split(key, fields, SUBSEP)
        mean = int((sum[key] + count[key] / 2) / count[key])
        print fields[1], fields[2], fields[3], count[key], minimum[key], mean, maximum[key], semantic[key], code[key], data[key], mapped[key], instructions[key], vectors[key], fixture[key]
    }
}
