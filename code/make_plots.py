# make_plots.py

"""
Code makes plots using the cost model
"""
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import matplotlib.cm
import json, os, sys
sys.path.append(os.path.join(os.getcwd(), 'code'))
from config import *
from model import *

## plotting settings:
plt.rcParams.update({'font.size': 12})
cmap = matplotlib.cm.get_cmap('tab20c')
cpal = ['k', cmap(0), cmap(2), cmap(4), cmap(7)]

## where to store plots
pic_path = os.path.join(os.getcwd(), 'plots')
if not os.path.isdir(pic_path):
    os.mkdir(pic_path)

## ---- functions ---- ##
## vary the ratio of hard malware files:
def plot_varying_hfr(ax = None, savepath=None, tool_dict = tool_dict, format = 'png'):
    if ax is None:
        fig, ax = plt.subplots(figsize = (5,3.5))
    hfr_grid = np.arange(0, .25, .005)
    for i, tool_name in enumerate(tool_dict.keys()):
        tool_entry=tool_dict[tool_name]
        costs = [ run_cost_model(
                    tool_entry['results'],
                    tool_entry['resource'],
                    hard_files_ratio = hfr)[-1]
                for hfr in hfr_grid]
        # print(tool_name, costs)
        ls = 'dotted' if i==0 else 'solid'
        ax.plot(hfr_grid, costs, '-', lw = 2, ls = ls,label = tool_name, c= cpal[i])
        ax.set_xlabel(r"Percent" );
        ax.set_ylabel('Cost ($)')
        ax.set_xlim(-.01, .251)
        # ax.set_ylim(0, x_max * 3.5E6/4000)
    ax.legend(fontsize=11)
    if savepath is not None:
        fig.tight_layout()
        fig.savefig(savepath, format = format)


def plot_varying_M(ax = None, savepath=None, x_max = 2500, format = 'eps'):
    if ax is None:
        fig, ax = plt.subplots(figsize = (5,3.5))
    max_cost_grid = np.arange(0, x_max+100, 100)
    for i, tool_name in enumerate(tool_dict.keys()):
        tool_entry=tool_dict[tool_name]
        costs = [run_cost_model(tool_entry['results'], resource = tool_entry['resource'], max_cost = max_cost)[-1] for max_cost in max_cost_grid]

        ls = 'dotted' if i==0 else 'solid'
        ax.plot(max_cost_grid, costs, '-', lw = 2, ls = ls,label = tool_name, c= cpal[i])
        ax.set_xlabel(r'$M (\$)$');
        ax.set_ylabel('Cost ($)')
        ax.set_xlim(0, x_max)
        ax.set_ylim(0, x_max * 3.5E6/1500) ## for original plot in paper (zoomed in one) this was set to (x_max + 1500)*3.5E6/4000
    ax.legend(fontsize=11)
    if savepath is not None:
        fig.tight_layout()
        fig.savefig(savepath, format = format)
    else: fig.show()

if __name__ == '__main__':

    # --- attack cost function plot --- ##
    plt.rcParams.update({'font.size': 12})
    cmap = matplotlib.cm.get_cmap('tab20c')
    T = np.arange(0,50*60,.5)
    c = list(map( attack_cost_f, T))
    plt.plot(T,c, c =cmap(0))
    plt.xlabel('Seconds')
    plt.ylabel('Dollars')
    plt.hlines(MAX_COST, 0, T[-1], colors=cmap(8), linestyles='dashed', label = r"M (max. cost)= $2,000")
    plt.vlines(ALPHA, 0, MAX_COST/2, colors=cmap(4), linestyles='dotted', label = r"$\alpha$ (time of .5 M) = 900s", linewidth = 1)
    plt.hlines(MAX_COST/2, 0, ALPHA, colors=cmap(4), linestyles='dashed')
    plt.legend(loc = 4)
    # plt.text( ALPHA_100, 100, r"$\alpha $")
    # plt.show()
    plt.savefig(os.path.join( pic_path, 'attack-cost.png') , format='png')
    # plt.savefig(os.path.join( pic_path, 'attack-cost.eps') , format='eps')
    ###

    ## ---- make dataframes ---- ##
    ## read in data
    df = pd.read_csv(os.path.join(".", "fake_data_table.csv")) ## reads in data

    ## make data per tool:
    df1 = df[['filename', 'filetype', 'malicious', 'polyglot', 'zero_day','time_to_detect_1']].rename({"time_to_detect_1": "time_to_detect"}, axis =1) ## first tool's results only
    df2 = df[['filename', 'filetype', 'malicious', 'polyglot', 'zero_day','time_to_detect_2']].rename({"time_to_detect_2": "time_to_detect"}, axis =1) ## second tool's results only

    #make simulated detectors results:
    no_alert_baseline_results = df1.copy()
    no_alert_baseline_results['time_to_detect'] = np.nan

    all_alert_baseline_results = no_alert_baseline_results.copy()
    all_alert_baseline_results['time_to_detect'] = 1E-10

    perfect_baseline_results = no_alert_baseline_results.copy()
    perfect_baseline_results.loc[perfect_baseline_results.malicious, 'time_to_detect'] = 1E-10
    perfect_baseline_results.loc[~perfect_baseline_results.malicious, 'time_to_detect'] = np.nan

    ## make dict of cost items we need for each tool:
    tool_dict = {   'Tool 1': {'results': df1, 'resource' : TOOL1_RESOURCE},
                    'Tool 2': {'results': df2, 'resource' : TOOL2_RESOURCE},
                    'Never Alert': {'results': no_alert_baseline_results, 'resource' : AVE_RESOURCE},
                    'Always Alert': {'results': all_alert_baseline_results, 'resource' : AVE_RESOURCE},
                    'Perfect Detector': {'results': perfect_baseline_results, 'resource': AVE_RESOURCE}}


    plot_varying_hfr()
    plot_varying_hfr(savepath = os.path.join(pic_path, 'vary-hfr.png') )
    # plot_varying_hfr(savepath = os.path.join(pic_path, 'vary-hfr.eps'), format = "eps" )

    plot_varying_M()

    # plot_varying_M(savepath = os.path.join(pic_path, 'vary-M-zoom-intersections.eps') , format='eps')
    plot_varying_M(savepath = os.path.join(pic_path, 'vary-M-zoom-intersections.png') , format='png')
    plot_varying_M(savepath = os.path.join(pic_path, 'vary-M-zoom-out.png') , x_max = 100000, format='png')
