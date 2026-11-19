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
    plt.savefig("results/Median.png")

algorithm_operation_median(df)