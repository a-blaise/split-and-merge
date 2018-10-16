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
from apyori import apriori
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

from Settings import *
from Features import Feature, list_features
from full_detection import path_join

def sign_to_score(row):
    if type(row) is str:
        total = 0
        nbs = row.split(',')
        total = int(nbs[0]) + int(nbs[1][1:])
        return int(total)
    else:
        return 0

def get_single_item(x):
    minus_item = -1
    plus_item = -1

    for char in list(str(x)):
        if char.isdigit():
            if plus_item == -1:
                plus_item = int(char)
            else:
                    minus_item = int(char)

    if minus_item == 0:
        if plus_item != 0:
            rep = plus_item
    else:
        if plus_item != 0:
            rep = - minus_item + plus_item
        else:
            rep = - minus_item
    return rep

def clustering_anomalies():
    value = pd.read_csv(path_join([PATH_PACKETS, 'packets_subnets_separated', PERIOD], 'csv'))
    list_anomalies = []
    list_annotations = []

    labels = []
    ports_annot = pd.read_csv(path_join([PATH_EVAL, 'eval_total_separated', PERIOD, T, N_MIN, N_DAYS, 'score'], 'csv'), sep = ';', index_col = 0)
    ports = ports_annot.applymap(sign_to_score)
    ports = ports.loc[(ports > THRESHOLD_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(dates[N_DAYS:]):
            if row[i] > THRESHOLD_ANO:
                annotations = []
                labels.append('port ' + str(index) + ' on ' + date[0:2] + '/' + date[2:])
                for feat in list_features:
                    if feat.attribute != 'nb_packets':
                        evaluation = pd.read_csv(path_join([PATH_EVAL, 'eval', feat.attribute, 'separated', PERIOD, T, N_MIN, N_DAYS, 'score'], 'csv'), sep = ';')
                        rep = evaluation[evaluation.port == index].loc[:, date]
                        if rep.empty == False:
                            if str(rep.item()) == 'nan':
                                annotations.append(0)
                                annotations.append(0)
                            else:
                                annotations.append(int(rep.item().split(',')[0][1:]))
                                annotations.append(int(rep.item().split(',')[1][1:]))
                                # get_single_item(rep.item()) # for now, replace each value by the sum of two values ( - x + y)
                        else:
                            annotations.append(0)
                            annotations.append(0)
                list_annotations.append(annotations)

    columns = []
    for feat in list_features:
        if feat.attribute != 'nb_packets':
            columns.append('+' + feat.attribute)
            columns.append('-' + feat.attribute)
    # columns = [feat.attribute for feat in list_features if feat.attribute != 'nb_packets']

    heatmap = pd.DataFrame(list_annotations, columns=columns, index = labels)
    to_drop = ['SYN']
    # heatmap = heatmap.drop(['+SYN', '-SYN', '+dst_div_index', '-dst_div_index'], axis=1)
    heatmap.drop(['+' + feature for feature in to_drop], axis=1)
    heatmap.drop(['-' + feature for feature in to_drop], axis=1)

    # Set all vectors to the same scale
    X = StandardScaler().fit_transform(heatmap)

    # 3.65 good value for 2016 with THRESHOLD_ANO = 10
    # ['port 23 on 08/04']
    # ['+src_div_index', '+dst_div_index']
    # ['port 23 on 08/11', 'port 3389 on 09/29', 'port 6379 on 06/16', 'port 6379 on 06/30']
    # ['+src_div_index', '+dst_div_index']
    # ['port 23 on 10/06', 'port 25 on 08/25', 'port 443 on 07/21', 'port 443 on 09/08', 'port 443 on 10/06', 'port 3128 on 08/18']
    # ['+src_div_index', '+dst_div_index']
    # ['port 2323 on 09/15']
    # ['+src_div_index', '+dst_div_index']
    epsilon = 3.65
    db = DBSCAN(eps=epsilon, min_samples=1).fit(X)
    labels = db.labels_
    core_samples_mask = np.zeros_like(labels, dtype=bool)
    core_samples_mask[db.core_sample_indices_] = True

    n_clusters_ = len(set(labels))

    for i in range(n_clusters_):
        specs = []
        anomalies = []
        for j in range(len(labels)):
            if labels[j] == i:
                temp = heatmap.iloc[j].values.tolist()
                sub_specs = []
                anomalies.append(heatmap.iloc[j].name)
                for k, x in enumerate(temp):
                    if x != 0:
                        if x > 0:
                            rep = '+'
                        else:
                            rep = '-'
                        rep += list_features[k % 2 +1].attribute
                        sub_specs.append(rep)
                specs.append(sub_specs)
        print(anomalies)
        find_common(i, specs) # --> step 1
        # apriori_algorithm(i, specs) # --> step 2  

def find_common(i, cluster):
    final_specs = []
    for feat in list_features[1:]:
        temp_sign = ''
        for el in cluster: # el : vector with all features
            for item in el:
                if feat.attribute in item:
                    ind = item.index(feat.attribute)
                    if item[0] == temp_sign:
                        temp_sign = item[0]
                    else:
                        if temp_sign == '':
                            temp_sign = item[0]
                        else:
                            temp_sign = ''
                            break
        if temp_sign != '':
            final_specs.append(temp_sign + feat.attribute)
    print(final_specs)

def apriori_algorithm(i, cluster):
    results = list(apriori(cluster))
    # print(i, results)

def main(argv):
    clustering_anomalies()
    return 0

if __name__ == '__main__':
    main(sys.argv)