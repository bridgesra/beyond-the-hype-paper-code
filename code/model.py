
"""
Cost model code with examples.
Basic usage is
    - run run_cost_model() function
    - pass a dataframe with only a single tool's results dataframe (so the file columns and a single time_to_detect column)
    - pass other globals cost estimate inputs
It returns a 4-tuple: ave_hard_malware_cost, ave_easy_malware_cost, ave_benign_cost, cost
with the last entry the total cost.
"""

import pandas as pd
import numpy as np
import json, os, sys
sys.path.append(os.path.join(os.getcwd(), 'to_share'))
from config import *


## --- functions for cost model --- ##
## S curve, alpha = time of half max cost is achieved, Max cost = asymptotic limit
def attack_cost_f(t, max_cost = MAX_COST, alpha = ALPHA):
    if t == 0:
        return 0
    if np.isnan(t):
        return max_cost
    return max_cost * 2**( - 1 / ( (t/alpha)**2 ))


### following two functions compute costs stemming from all tested malware and simulated benignware costs to match the malware:benignware ratio:
def get_ave_malware_cost(df_tool_results, resource, attack_cost_f = attack_cost_f, max_cost = MAX_COST, alpha = ALPHA, labor = LABOR):
    """
    Description:
        outputs the ave cost per malware
        estimate uses all malware tested (attack costs for all malware + triage and IR cost for detected malware)
    Inputs:
        df_tool_results = table of results per file for this tool
        resource = dict of resource costs per tool (pass it a global)
        attack_cost_f = function of time, (and globals: max_cost, alpha) giving cost of an attack per time it was ongoing.
        labor = dict of labor costs
    """
    total_attack_cost = sum(map( lambda t: attack_cost_f(t, max_cost, alpha) , list( df_tool_results[df_tool_results.malicious].time_to_detect ) ))
    tp = df_tool_results[ (df_tool_results.malicious) & (~df_tool_results.time_to_detect.isna()) ].shape[0] ## number of true alerts
    total_triage_ir_costs = tp * (resource["triage"] + labor['triage'] + labor["ir"])
    n_mal = sum(df_tool_results.malicious)
    if n_mal == 0:
        return 0
    return ( total_attack_cost + total_triage_ir_costs ) / n_mal


def get_ave_benign_cost(df_tool_results, resource, labor = LABOR, verbose = False):
    """
    Description:
        outputs the ave cost of a benignware sample using all benignware from the test
    Input:
        df_tool_results = table of results per file for this tool
        resource = dict of resource for this tool (pass it a global)
    """
    ### false positive results from the benign files in the data
    n_benign = sum(~df_tool_results.malicious)

    if n_benign == 0: fpr=0
    else: fpr = df_tool_results[(~df_tool_results.malicious) & (~df_tool_results.time_to_detect.isna())].shape[0]/n_benign

    if verbose: print (f"\tFPR: {fpr}")

    return  (resource['triage'] + labor['triage']) * fpr


def cost_estimate(ave_benign_cost, ave_hard_malware_cost, ave_easy_malware_cost, resource, labor = LABOR, malware_ratio= MALWARE_RATIO, hard_files_ratio = .05, total_files_per_year = TOTAL_FILES_PER_YEAR, years = 1):
    """
    Input:
        ave_easy_malware_cost/ ave_hard_malware / ave_benign_cost = float, output of get_ave_malware/benignware cost above, gives ave cost from malicious/benign testing data
        resource = dict, global, resource costs defined for each tool
        labor = dict global labor costs
        malware_ratio= percent of files that are malware
        hard_files_ratio = percent of malware that are hard files (zero days, e.g.)
        total_files_per_year = int/float global, gives number of files per year
        years = int/float, giving number of years for the cost estimate
    Output: cost estimate for using the tool over first years (input) years
    """
    n_hard = total_files_per_year * malware_ratio * hard_files_ratio
    n_easy = total_files_per_year * malware_ratio * (1 - hard_files_ratio)
    n_benign = total_files_per_year * ( 1 - malware_ratio )

    cost = (
            resource['initial'] + labor['initial'] + ## initial hw and config time
            years * (
                    resource['base_rate'] + labor['base_rate'] + ## yearly cost of subscriptions, appliance electricity/cooling, reconfiguration labor
                    n_hard * ave_hard_malware_cost +  ## yearly cost of hard attacks
                    n_easy * ave_easy_malware_cost + ## yearly cost of easy attacks
                    n_benign * ave_benign_cost  ## yearly cost of false positives
                )
            )
    return cost


def run_cost_model(df_tool_results, resource, labor = LABOR,
    malware_ratio= MALWARE_RATIO, total_files_per_year = TOTAL_FILES_PER_YEAR,
    max_cost = MAX_COST, hard_cost_multiplier= HARD_COST_MULTIPLIER, hard_files_ratio = HARD_FILES_RATIO, alpha = ALPHA, attack_cost_f = attack_cost_f,
    years = YEARS, verbose = False):
    """
    Inputs:
        df_tool_results = dataframe of a tool's results
        resource = resource dict for a tool (pass a global)
        labor = labor dict (global)
        malware_ratio = float in [0,1] giving percent of files expected to be malicious
        total_files_per_year = number of files in a year expected
        max_cost = postitive float, max costs for not detecting an easy malware file
        hard_cost_multiplier = positive float giving multiplier of max_cost to get the max cost of a hard malware file that goes undetected
        hard_files_ratio = float in [0,1], gives the fraction of malware files that are hard (zerodays OR polygots OR APTs)
        alpha = half time cost for attack cost function
        attack_cost_f = attack cost function of time
        years = postive float, number of years for the cost estimate
        verbose = bool indicator for printouts
    Outputs: ave_hard_malware_cost, ave_easy_malware_cost, ave_benign_cost, cost (all floats)
    """

    ave_benign_cost = get_ave_benign_cost(df_tool_results, resource = resource, labor = labor, verbose = verbose)

    ### this makes the cost of hard malware different than the cost of the rest
    mask = (df_tool_results.zero_day) | (df_tool_results.polyglot) | (df_tool_results.filetype == "APT") ## hard files mask
    ave_hard_malware_cost = get_ave_malware_cost(df_tool_results[mask], resource = resource, attack_cost_f = attack_cost_f, max_cost = max_cost*hard_cost_multiplier, alpha = ALPHA, labor = LABOR)
    ave_easy_malware_cost = get_ave_malware_cost(df_tool_results[~mask], resource = resource, attack_cost_f = attack_cost_f, max_cost = max_cost, alpha = ALPHA, labor = LABOR)

    cost = cost_estimate(ave_benign_cost, ave_hard_malware_cost, ave_easy_malware_cost,  resource, labor = labor, malware_ratio = malware_ratio, hard_files_ratio = hard_files_ratio, total_files_per_year = total_files_per_year)
    if verbose:
        print(f'\tAve Benign Cost: ${ave_benign_cost:,.2f}')
        print(f'\tAve Hard Malware Cost: ${ave_hard_malware_cost:,.2f}')
        print(f'\tAve Easy Malware Cost: ${ave_easy_malware_cost:,.2f}')
        print(f'\t1 Year Cost: ${cost:,.2f}')
    return ave_hard_malware_cost, ave_easy_malware_cost, ave_benign_cost, cost


def get_cost_diff_adding_network_tool(df, network_tool_colname = "time_to_detect_2", host_tool_colname = "time_to_detect_1", resource = TOOL2_RESOURCE, years = 1, max_cost = MAX_COST, verbose = True ):
    """
    Computes cost/savings of adding network tool to host tool.
    """

    global LABOR
    global ALPHA

    #build alert intersection dataframes
    fp_network_df= df[~(df.malicious) & (~df[network_tool_colname].isna())] ## benign but tool 2 detected it
    tp_network_df= df[(df.malicious) & (~df[network_tool_colname].isna())].reset_index(drop=True) ## malicious & tool 2 detected it
    tp_network_only_df = tp_network_df[tp_network_df[host_tool_colname].isna()] ## malicious & tool 1 did not detect & tool 2 did detect it

    #compute ave cost differences for benign and malware
    ave_cost_diff_benign = (resource['triage'] + LABOR['triage'])*len(fp_network_df)/sum(~df.malicious)
    attack_cost_sum = sum(map( lambda t: attack_cost_f(t, max_cost, ALPHA), list( tp_network_only_df[network_tool_colname]) ))
    ave_cost_diff_malware = ((resource['triage'] + LABOR['triage'])*len(tp_network_df) + (LABOR['ir']-max_cost)*len(tp_network_only_df) + attack_cost_sum)/sum(df.malicious)


    total_cost_diff = cost_estimate(
        ave_cost_diff_benign,
        ave_cost_diff_malware,
        ave_cost_diff_malware,
        resource,
        labor = LABOR,
        years = years
        )

    if verbose:
        print(f'Cost Difference adding Tool 2 (network detector) to Tool 1 (host detector):')
        print(f'\tAverage Benign Cost Difference: ${ave_cost_diff_benign:,.2f}')
        print(f'\tAverage Malware Cost Difference: ${ave_cost_diff_malware:,.2f}')
        n_mal = TOTAL_FILES_PER_YEAR * MALWARE_RATIO
        n_benign = TOTAL_FILES_PER_YEAR * ( 1 - MALWARE_RATIO )
        print(f"\tWeighted Costs: Malware: ${n_mal * ave_cost_diff_malware:,.2f}, Benign: ${n_benign * ave_cost_diff_benign:,.2f}")
        print(f'\tTotal Cost Difference for {years} year(s): ${total_cost_diff:,.2f}')

    return  ave_cost_diff_benign, ave_cost_diff_malware, total_cost_diff


if __name__ == '__main__':
    df = pd.read_csv(os.path.join("to_share", "fake_data_table.csv")) ## reads in data

    ## make data per tool:
    df1 = df[['filename', 'filetype', 'malicious', 'polyglot', 'zero_day','time_to_detect_1']].rename({"time_to_detect_1": "time_to_detect"}, axis =1) ## first tool's results only
    df2 = df[['filename', 'filetype', 'malicious', 'polyglot', 'zero_day','time_to_detect_2']].rename({"time_to_detect_2": "time_to_detect"}, axis =1) ## second tool's results only

    ## example cost model use:
    print("First tool:")
    run_cost_model(df1, TOOL1_RESOURCE, verbose = True)

    print("Second tool:")
    run_cost_model(df2, TOOL2_RESOURCE, verbose = True)

    #make simulated detectors results:
    no_alert_baseline_results = df1.copy()
    no_alert_baseline_results['time_to_detect'] = np.nan

    all_alert_baseline_results = no_alert_baseline_results.copy()
    all_alert_baseline_results['time_to_detect'] = 1E-10

    perfect_baseline_results = no_alert_baseline_results.copy()
    perfect_baseline_results.loc[perfect_baseline_results.malicious, 'time_to_detect'] = 1E-10
    perfect_baseline_results.loc[~perfect_baseline_results.malicious, 'time_to_detect'] = np.nan

    print("Never alert baseline:")
    run_cost_model(no_alert_baseline_results, AVE_RESOURCE, verbose = True)

    print("Always alert baseline:")
    run_cost_model(all_alert_baseline_results, AVE_RESOURCE, verbose = True)

    print("Perfect detection baseline:")
    run_cost_model(perfect_baseline_results, AVE_RESOURCE, verbose = True)

    ## now run complementary cost model
    print ("Is it worth adding network tool (2) to host tool (2)?")
    get_cost_diff_adding_network_tool(df)
