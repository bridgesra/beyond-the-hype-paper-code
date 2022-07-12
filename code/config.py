# config.py

## -- global variables needed for cost function-- ##

## cost function variables:
MAX_COST = 2000 ## dollars
ALPHA = 60 * 15 ## 15 minutes

HARD_COST_MULTIPLIER =  10 # multiplier of max_cost to get the max cost of a hard malware file that goes undetected.
## setting HARD_COST_MULTIPLIER = 1 makes all malware have same cost.
HARD_FILES_RATIO = .05 # gives the fraction of malware files that are hard (zerodays OR polygots OR APTs)

## scale variables
MALWARE_RATIO = 0.0116 ## from Li et al. 2017
TOTAL_FILES_PER_YEAR = 500 * 50 * 5 ### estimate from SOC interview, 500 files per day per 1K IPs times 50 work weeks per year * 5 workdays per week

## resource costs:
TOOL1_RESOURCE = {
    'initial' : 1000, ## appliance cost,
    'base_rate': 10000, ## yearly subscription fee
    'triage': 0.05 ## cost per alert into splunk
    }

TOOL2_RESOURCE = {
    'initial' : 20000, ## appliance cost,
    'base_rate': 15000, ## yearly subscription fee
    'triage': 0.05## cost per alert into splunk
    }

## used for simulated detectors
AVE_RESOURCE = {
    'initial' : 10500, ## appliance cost,
    'base_rate': 12500, ## yearly subscription fee
    'triage': 0.05## cost per alert into splunk
    }


## labor costs  ( and taken from our paper)
LABOR = {
    'initial' : 8*70, ## initial config cost = 8 manhours * $70/hr (wage + overhead)
    'base_rate': 8 * 70 * 12, ## yearly continual tweaking cost = 8 manhours/month * 70/hr * 12 months
    'triage': 70, ## cost per alert to triage = most handled in 10 min, portion handled by Tier 2 which takes 10min+, took average
    'ir': 280, ## cost to investigate a true positive after triage = 4 hours * 70/hour
    }

## years to run the model
YEARS = 1
