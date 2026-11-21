import matplotlib.pyplot as plt
import pandas as pd
import numpy as np



df = pd.read_csv("results/benchmark.csv")
runs = pd.read_csv("results/runs.csv")


def algorithm_operation_median(df: pd.DataFrame) -> None:
    m = df.groupby(["algorithm", "operation"])["time_ns"].apply(np.median)
    m.name = "Median"


    plt.figure(figsize=(12, 12))
    m.plot(kind='bar', color='coral', width=0.6)
    plt.title("Which operations dominate execution time on the Raspberri Pi?")
    plt.xlabel("Algorithm / Op")
    plt.ylabel("Time (ns)")
    plt.xticks(rotation=25)
    plt.savefig("results/figs/median.png")



def ratio_keys_n_exchange_sizes(df: pd.DataFrame) -> None:
    subset = df.groupby(["algorithm", "operation"])["output_size"]
    s = subset.first()

    # returns a subset whith only the public key size and removes the operation column of the df
    pub = s.xs("keygen", level="operation")
    priv = s.xs("privkey-serialization", level="operation")

    # exchanged takes into account the sum of all the elements shared during the operation
    exchanged = pd.Series({
        "ECDH P-256": pub["ECDH P-256"] * 2,
        "ML-KEM-768": pub["ML-KEM-768"] + s["ML-KEM-768", "encapsulation"]
    })

    table = pd.DataFrame({
        "public key size" : pub,
        "private key size": priv,
        "exchange size"   : exchanged        
    })

    plt.figure(figsize=(10, 6))
    table.T.plot(kind='bar', width=0.6,
                color={"ECDH P-256": "steelblue", "ML-KEM-768": "coral"})

    plt.title("How different are the key and exchanged-data sizes?")
    plt.ylabel("Size (bytes)")
    plt.xticks(rotation=0)
    plt.savefig("results/figs/sizes.png")



# counts how many network packets each algorithm needs per handshake on a
# wired link (Ethernet MTU) and on a constrained radio link (LoRaWAN), ignoring
# protocol headers, to judge whether ML-KEM's extra bytes matter on each link.
def communication_overhead(df: pd.DataFrame) -> None:
    s = df.groupby(["algorithm", "operation"])["output_size"].first()
    messages = {
        "ECDH P-256": [s["ECDH P-256", "keygen"], s["ECDH P-256", "keygen"]],
        "ML-KEM-768": [s["ML-KEM-768", "keygen"], s["ML-KEM-768", "encapsulation"]],
    }
    links = {"Ethernet (1500 B)": 1500, "LoRaWAN (242 B)": 242, "LoRaWAN SF12 (51 B)": 51}

    packets = pd.DataFrame({
        link: {alg: int(sum(np.ceil(m / limit) for m in msgs)) for alg, msgs in messages.items()}
        for link, limit in links.items()
    })
    total = pd.Series({alg: sum(msgs) for alg, msgs in messages.items()}, name="bytes per handshake")
    print(pd.concat([total, packets], axis=1).to_string())
    print("extra bytes per handshake:", total["ML-KEM-768"] - total["ECDH P-256"])

    ax = packets.T.plot(kind="bar", figsize=(10, 6), width=0.6,
                        color={"ECDH P-256": "steelblue", "ML-KEM-768": "coral"})
    ax.bar_label(ax.containers[0])
    ax.bar_label(ax.containers[1])
    plt.title("Does ML-KEM introduce significant communication overhead?")
    plt.ylabel("Packets per handshake")
    plt.xticks(rotation=0)
    plt.savefig("results/figs/overhead.png")



# measures how stable each operation's timing is across repetitions (IQR,
# coefficient of variation, Tukey outliers, bootstrap 95% CI of the median) and
# plots the distributions and the rolling median to reveal drift over the run.
def timing_stability(df: pd.DataFrame) -> None:
    rng = np.random.default_rng(0)
    rows = {}
    for (alg, op), g in df.groupby(["algorithm", "operation"]):
        t = g["time_ns"].to_numpy()
        q1, med, q3 = np.percentile(t, [25, 50, 75])
        iqr = q3 - q1
        boot = np.median(rng.choice(t, size=(1000, t.size), replace=True), axis=1)
        rows[(alg, op)] = {
            "median": med,
            "mean": t.mean(),
            "IQR": iqr,
            "CV": t.std() / t.mean(),
            "outliers": int((t > q3 + 1.5 * iqr).sum() + (t < q1 - 1.5 * iqr).sum()),
            "CI95 low": np.percentile(boot, 2.5),
            "CI95 high": np.percentile(boot, 97.5),
        }
    stats = pd.DataFrame(rows).T
    print(stats.round(3).to_string())

    groups = df.groupby(["algorithm", "operation"])["time_ns"]
    labels = [f"{alg}\n{op}" for alg, op in groups.groups.keys()]
    plt.figure(figsize=(14, 7))
    plt.boxplot([g.to_numpy() for _, g in groups], showfliers=False)
    plt.xticks(range(1, len(labels) + 1), labels, fontsize=8)
    plt.yscale("log")
    plt.title("Are the timing differences stable across repeated runs?")
    plt.ylabel("Time (ns, log scale)")
    plt.savefig("results/figs/stability_boxplot.png")

    plt.figure(figsize=(14, 7))
    for (alg, op), g in df.groupby(["algorithm", "operation"]):
        g = g.sort_values("repetition")
        plt.plot(g["repetition"] / g["repetition"].max(),
                 g["time_ns"].rolling(50).median(), label=f"{alg} {op}")
    plt.yscale("log")
    plt.title("Rolling median (window 50) over the benchmark")
    plt.xlabel("Fraction of repetitions completed")
    plt.ylabel("Time (ns, log scale)")
    plt.legend(fontsize=8)
    plt.savefig("results/figs/stability_drift.png")



# compares each measured size with the value fixed by the specification
# (SEC 1 for P-256, FIPS 203 for ML-KEM-768) and lists the implementation stack
# of each algorithm, separating mechanism-driven from implementation-driven results.
def mechanism_vs_implementation(df: pd.DataFrame) -> None:
    spec = pd.Series({
        ("ECDH P-256", "keygen"): 65,
        ("ECDH P-256", "derivation"): 32,
        ("ECDH P-256", "privkey-serialization"): 32,
        ("ML-KEM-768", "keygen"): 1184,
        ("ML-KEM-768", "encapsulation"): 1088,
        ("ML-KEM-768", "decapsulation"): 32,
        ("ML-KEM-768", "privkey-serialization"): 2400,
    }, name="spec size")
    measured = df.groupby(["algorithm", "operation"])["output_size"].first().rename("measured size")
    sizes = pd.concat([measured, spec], axis=1)
    sizes["matches spec"] = sizes["measured size"] == sizes["spec size"]
    print(sizes)

    stack = df[["algorithm", "config", "library", "version", "governor_policy"]].drop_duplicates()
    print(stack.to_string(index=False))



# summarises the Raspberry Pi conditions recorded per run (temperature,
# frequency) and measures whether temperature correlates with
# operation time, to document the limits of the comparison.
def benchmark_conditions(df: pd.DataFrame, runs: pd.DataFrame) -> None:
    print(runs["temp_c"].agg(["min", "median", "max"]))
    print("frequencies (kHz):", runs["freq_khz"].unique())

    binary = {"ECDH P-256": "./bin/ecdh", "ML-KEM-768": "./bin/mlkem"}
    per_run = {"ECDH P-256": 2, "ML-KEM-768": 1}
    d = df.copy()
    d["binary"] = d["algorithm"].map(binary)
    d["run"] = (d["repetition"] + d["algorithm"].map(per_run) - 1) // d["algorithm"].map(per_run)
    d = d.merge(runs[["run", "binary", "temp_c"]], on=["run", "binary"])

    corr = d.groupby(["algorithm", "operation"])[["temp_c", "time_ns"]].apply(
        lambda g: g["temp_c"].corr(g["time_ns"], method="spearman"))
    print(corr.rename("spearman temp vs time").round(3))

    plt.figure(figsize=(10, 6))
    for alg, color in {"ECDH P-256": "steelblue", "ML-KEM-768": "coral"}.items():
        g = d[d["algorithm"] == alg]
        plt.scatter(g["temp_c"], g["time_ns"], s=4, alpha=0.3, color=color, label=alg)
    plt.yscale("log")
    plt.title("Does temperature affect operation time?")
    plt.xlabel("SoC temperature before the run (°C)")
    plt.ylabel("Time (ns, log scale)")
    plt.legend()
    plt.savefig("results/figs/temperature.png")


algorithm_operation_median(df)
ratio_keys_n_exchange_sizes(df)
communication_overhead(df)
timing_stability(df)
mechanism_vs_implementation(df)
benchmark_conditions(df, runs)
