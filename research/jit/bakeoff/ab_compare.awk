BEGIN {
    FS = ","
    OFS = ","
}

FNR == NR && FNR > 1 && $2 == "jit" && $3 == "direct_lease_call" {
    before_min[$1] = $5
    before_mean[$1] = $6
    before_max[$1] = $7
    next
}

FNR != NR && FNR > 1 && $2 == "jit" && $3 == "direct_lease_call" {
    after_min[$1] = $5
    after_mean[$1] = $6
    after_max[$1] = $7
}

END {
    print "cell", "result", "before_min_ns", "before_mean_ns", "before_max_ns", "after_min_ns", "after_mean_ns", "after_max_ns", "after_over_before"
    for (cell in before_mean) {
        if (after_mean[cell] < before_mean[cell]) result = "faster"
        else if (after_mean[cell] > before_mean[cell]) result = "slower"
        else result = "tie"
        if (before_mean[cell] == 0) ratio = "inf"
        else ratio = sprintf("%.4f", after_mean[cell] / before_mean[cell])
        print cell, result, before_min[cell], before_mean[cell], before_max[cell], after_min[cell], after_mean[cell], after_max[cell], ratio
    }
}
