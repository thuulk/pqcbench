import matplotlib.pyplot as plt
import pandas as pd
import numpy as np



df = pd.read_csv("results/benchmark.csv")



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




algorithm_operation_median(df)
ratio_keys_n_exchange_sizes(df)