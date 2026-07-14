BEGIN {
    FS = ","
    OFS = ","
}

NR == 1 { next }

$2 == "jit" && $3 == "direct_lease_call" {
    jit_min[$1] = $5
    jit_mean[$1] = $6
    jit_max[$1] = $7
}

$2 == "rust-regex-1.12.4" && $3 == "search" {
    regex_min[$1] = $5
    regex_mean[$1] = $6
    regex_max[$1] = $7
}

$2 == "fre-kernels" && $3 == "search" {
    kernels_min[$1] = $5
    kernels_mean[$1] = $6
    kernels_max[$1] = $7
}

END {
    print "cell", "comparison", "result", "jit_min_ns", "jit_mean_ns", "jit_max_ns", "other_min_ns", "other_mean_ns", "other_max_ns", "jit_over_other"
    for (cell in jit_mean) {
        emit(cell, "rust-regex-1.12.4", regex_min[cell], regex_mean[cell], regex_max[cell])
        emit(cell, "fre-kernels", kernels_min[cell], kernels_mean[cell], kernels_max[cell])
    }
}

function emit(cell, comparison, other_min, other_mean, other_max, result, ratio) {
    if (jit_mean[cell] < other_mean) result = "win"
    else if (jit_mean[cell] > other_mean) result = "loss"
    else result = "tie"
    if (other_mean == 0) ratio = "inf"
    else ratio = sprintf("%.4f", jit_mean[cell] / other_mean)
    print cell, comparison, result, jit_min[cell], jit_mean[cell], jit_max[cell], other_min, other_mean, other_max, ratio
}
