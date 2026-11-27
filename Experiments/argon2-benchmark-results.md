
# Argon2id Performance Evaluation

## 1. Objective

This experiment evaluates the performance of Argon2id password hashing and verification under three different parameter configurations.

The objective is to identify a reasonable baseline configuration for the authentication component of the secure banking information system.

## 2. Experimental Environment

| Component | Version / Configuration |
|---|---|
| Operating System | Windows 11 |
| Python | 3.12.10 |
| argon2-cffi | 25.1.0 |
| Hash Algorithm | Argon2id |
| Hash Length | 32 bytes |
| Salt Length | 16 bytes |
| Measured Operations | 5 per operation and configuration |

Each configuration received one warm-up operation before measurements. The reported results are based on five measured hashing operations and five measured verification operations.

## 3. Tested Configurations

| Configuration | Memory | Iterations | Parallelism |
|---|---:|---:|---:|
| A — Lightweight | 19 MiB | 2 | 1 |
| B — Current Baseline | 64 MiB | 3 | 4 |
| C — Higher Memory | 128 MiB | 2 | 4 |

## 4. Experimental Results

### 4.1 Median Latency

| Configuration | Hashing | Verification |
|---|---:|---:|
| A — Lightweight | 25.75 ms | 23.32 ms |
| B — Current Baseline | 47.12 ms | 44.68 ms |
| C — Higher Memory | 82.76 ms | 80.06 ms |

### 4.2 Observations

- Configuration A provided the lowest measured latency.
- Configuration B provided an intermediate balance between memory usage and measured latency.
- Configuration C required the most memory and had the highest measured latency.
- Configuration C showed noticeable variation in hashing measurements, ranging from 64.12 ms to 163.11 ms.

## 5. Preliminary Configuration Decision

Configuration B is retained as the provisional baseline:

| Parameter | Selected Value |
|---|---|
| Algorithm | Argon2id |
| Memory Cost | 65,536 KiB |
| Time Cost | 3 |
| Parallelism | 4 |
| Hash Length | 32 bytes |
| Salt Length | 16 bytes |

The decision is provisional and will be reviewed through further performance and security evaluation.

## 6. Experimental Limitations

The experiment was conducted on a local Windows development machine using sequential operations.

Only five measured runs were performed per operation and configuration. Consequently, the results are preliminary and should not be interpreted as production capacity measurements.

Multiple parameters were changed simultaneously between configurations. Therefore, the experiment does not isolate the individual effect of memory cost, iteration count, or parallelism.

Further experiments should include:

1. Controlled parameter comparisons.
2. Larger sample sizes.
3. Concurrent authentication tests.
4. CPU and memory resource measurements.
5. Evaluation under realistic application workloads.

## 7. Conclusion

The experiment demonstrates that Argon2id can provide password hashing and verification with measurable local execution costs.

Configuration B is retained as the initial implementation baseline because it offers an intermediate performance and memory profile among the tested candidates.

Further evaluation is required before selecting final production parameters.