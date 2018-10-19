# Copyright 2018 @ Agathe Blaise.

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import os
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from Settings import *
from Features import Feature, list_features
from full_detection import path_join, pre_computation

def sign_to_score(row):
    total = 0
    if type(row) is str:
        nbs = row.split(',')
        total = int(nbs[0]) + int(nbs[1][1:])
    return total

def clustering_anomalies():
    value = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'))
    list_anomalies = []
    list_annotations = []

    indexes = []
    ports_annot = pd.read_csv(path_join([PATH_EVAL, 'eval_total_separated', PERIOD, T, N_MIN, N_DAYS, 'score'], 'csv'), sep = ';', index_col = 0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > THRESHOLD_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(dates[N_DAYS:]):
            if row[i] > THRESHOLD_ANO:
                annotations = []
                indexes.append('port ' + str(index) + ' on ' + date[0:2] + '/' + date[2:])
                for feat in list_features:
                    evaluation = pd.read_csv(path_join([PATH_EVAL, 'eval', feat.attribute, 'separated', PERIOD, T, N_MIN, N_DAYS, 'score'], 'csv'), sep = ';')
                    rep = evaluation[evaluation.port == index].loc[:, date]
                    if rep.empty == False:
                        if str(rep.item()) == 'nan':
                            annotations.extend([0, 0])
                        else:
                            annotations.extend([int(rep.item().split(',')[i][1:]) for i in range(2)])
                    else:
                        annotations.extend([0, 0])
                list_annotations.append(annotations)

    heatmap = pd.DataFrame(list_annotations, columns=[sign + feat.attribute for sign in ['+', '-'] for feat in list_features], index = indexes)
    
    to_drop = ['nb_packets', 'SYN', 'port_div_index']
    heatmap = heatmap.drop(['+' + feature for feature in to_drop], axis=1)
    heatmap = heatmap.drop(['-' + feature for feature in to_drop], axis=1)

    # Set all vectors to the same scale
    X = StandardScaler().fit_transform(heatmap)

    epsilon = 2.88 # essayer aussi de trouver un epsilon proportionnel en fonction du nombre de dimensions (= nbre de features * 2)
    db = DBSCAN(eps=epsilon, min_samples=1).fit(X)
    labels = db.labels_

    for i in range(len(set(labels))):
        print('Cluster ' + str(i + 1) + ':', [heatmap.iloc[j] for j, label in enumerate(labels) if label == i])

def main(argv):
    clustering_anomalies()
    return 0

if __name__ == '__main__':
    main(sys.argv)