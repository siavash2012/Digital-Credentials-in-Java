
#The code is implemented by Siavash Khalaj (skhal045@uottawa.ca)

import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
import scipy.stats as stats

df_dl = pd.read_csv("book_implementation_DL_result.txt", sep='\t', header=None, usecols=range(12))
df_ec = pd.read_csv("book_implementation_EC_result.txt", sep='\t', header=None, usecols=range(12))


def plot_results():
    width = 0.25  # the width of the bars
    fig, ax = plt.subplots(layout='constrained')
    offset = 0

    for i in range(12):
        ax.bar(offset, df_dl.loc[:,i].mean()/10**6, width, yerr=df_dl.loc[:,i].std()/10**6, capsize=5, color='#FF0000')
        ax.bar(offset + 0.25, df_ec.loc[:,i].mean()/10**6, width, yerr=df_ec.loc[:,i].std()/10**6, capsize=5, color='#00CCCC')
        offset += 0.75

    plt.legend(['Discrete Log', 'Elliptic Curve'])
    plt.ylabel('Time (ms)', fontsize=12, fontweight='bold')
    ax.set_title('Discrete Log Versus Elliptic Curve Timing', fontweight='bold', fontsize=18)
    x_ticks = np.arange(0.125, 9.125, 0.75)
    x_tick_labels = ["Obtain SIG",
                     "Verify SIG",
                     "Show 1 ATTR",
                     "Show 2 ATTR",
                     "Show 3 ATTR",
                     "Show 4 ATTR",
                     "Show 5 ATTR",
                     "Show 6 ATTR",
                     "Show 7 ATTR",
                     "Show 8 ATTR",
                     "Show 9 ATTR",
                     "Show 10 ATTR"]

    ax.set_xticks(x_ticks, x_tick_labels)
    plt.xticks(fontsize=12, rotation=45)
    plt.show()


def ttest_results():
    labels = ["Obtain Signature", "Verify Signature", "Show 1 Attribute", "Show 2 Attributes",
              "Show 3 Attributes", "Show 4 Attributes", "Show 5 Attributes", "Show 6 Attributes",
              "Show 7 Attributes", "Show 8 Attributes", "Show 9 Attributes", "Show 10 Attributes"]
    for i in range(12):
        result = stats.ttest_ind(a=df_dl.loc[:,i], b=df_ec.loc[:,i], equal_var=False)
        print(labels[i], result)


plot_results()
ttest_results()
