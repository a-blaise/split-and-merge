#!/usr/bin/env python3

import warnings
import numpy as np
import os

warnings.filterwarnings("ignore")

N_BATCH = 10 ** 6
N_DAYS = 10
N_MIN = 20
T = 3.5

THRESHOLD_ANO = 14

PERIOD = 2018 # or 2016

if PERIOD == 2016:
	dates = ['0331', '0407', '0414', '0421', '0428', '0505', '0512', '0519', '0526', '0602', '0609', '0616', '0622', '0630', 
		'0707', '0714', '0721', '0728', '0804', '0811', '0818', '0825', '0901', '0908', '0915' ,'0922', '0929', '1006', '1013', '1020']
elif PERIOD == 2018:
	dates = ['1026', '1102', '1109', '1116', '1123', '1130', '1207', '1214', '1221', '1228', '0104', '0111', '0118', '0125', '0201',
		'0208', '0215', '0222', '0301', '0308', '0315', '0322', '0329', '0405', '0412', '0419', '0426', '0503', '0510', '0517', '0524', '0531']

AGGs = [True, False]

ROOT_PATH = os.getcwd() + '/' # current directory

PATH_PCAPS = ROOT_PATH + 'pcaps/'
PATH_CSVS = ROOT_PATH + 'csvs/'
PATH_PACKETS = ROOT_PATH + 'packets/'
PATH_EVAL = ROOT_PATH + 'eval/'
PATH_HEATMAP = ROOT_PATH + 'heatmap/'
PATH_SUBNETS = ROOT_PATH + 'subnets/'
PATH_FIGURES = ROOT_PATH + 'figures/'

x = np.arange(len(dates))
y = np.arange(len(dates) - N_DAYS)