#!/usr/bin/env python3

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
import math
import os
from matplotlib.backends.backend_pdf import PdfPages
from Settings import *
from Features import Feature, Figure, list_features

# Lambda function to replace each non-zero value by its y-number
def value_to_yaxis(x):
    new_vector = x
    for (i, el) in enumerate(x):
        if el > 0:
            new_vector[i] = x.name
    return new_vector

# Lambda function to convert 
def sign_to_score(row):
    if type(row) is str:
        total = 0
        nbs = row.split(',')
        total = int(nbs[0]) + int(nbs[1][1:])
        return int(total)
    else:
        return 0

# Draws a panorama of the occurrences of anomaly score (corresponds to the number of anomalies on one port for all features in all subnetworks).
def heat_map_scores():
    value = pd.read_csv(str(PATH_PACKETS) + 'packets_subnets_agg_' + str(PERIOD) + '.csv')

    ports = pd.read_csv(PATH_EVAL + 'eval_total_separated_' + str(PERIOD) + '_' + str(T) + '_' 
        + str(N_MIN) + '_score.csv', sep = ';', index_col = 0)
    ports = ports.applymap(sign_to_score)
    result = ports.apply(pd.Series.value_counts).iloc[1:]
    annot_matrix = result.copy(deep=True)
    result.apply(value_to_yaxis, axis = 1)
    data_annot = np.array(annot_matrix)
    data = np.array(result)

    # Plot
    fig, ax = plt.subplots()
    im = ax.imshow(data, cmap='YlOrRd', aspect=.7)

    ax.set_ylabel('Anomaly score')
    ax.set_xlabel('Time')

    ax.set_yticks(np.arange(data.shape[0]))
    ax.set_xticks(np.arange(data.shape[1]))

    ax.set_yticklabels(result.index.values)
    ax.set_xticklabels([x[0:2] + '/' + x[2:] for x in result.columns.values])

    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=40, ha="right", rotation_mode="anchor")

    # Loop over data dimensions and create text annotations.
    for i in range(0, data.shape[0]):
        for j in range(0, data.shape[1]):
            if not math.isnan(data_annot[i, j]):
                color="black"
                if i > 10:
                    score = result.iloc[i,j]
                    df = ports.iloc[:, j]
                    port = df[df == score].index[0]
                    per = value[(value.date == int(dates[N_DAYS + j])) & (value.port == int(port))]['nb_packets'] / 10 ** 6 * 1000
                    print(per, int(dates[N_DAYS + j]), port)
                    per = int(round(per))
                    text = ax.text(j+0.55, i-0.13, port, color=color, size=6.5)
                    text = ax.text(j+0.55, i+0.45, per, color=color, size=6.5)
                if i > 12:
                    color="white"
                text = ax.text(j, i, int(data_annot[i, j]), 
                    ha="center", va="center", color=color, size=8)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    plt.savefig(PATH_FIGURES + 'heatmap_' + str(T) + '_' + str(N_MIN) + '_' + str(PERIOD) + '.png', dpi=600,bbox_inches='tight')

# Lambda function to sum two given scores, e.g., '+5, -4' becomes 9
def get_sum_string(x):
    total = 0
    for char in list(str(x)):
        if char.isdigit():
            total += int(char)
    return total

# Draws a better characterization of each major anomaly (anomaly score > THRESHOLD_ANO = 15) by providing the change in features this day.
def heatmap_anomalies():
    value = pd.read_csv(PATH_PACKETS + 'packets_subnets_separated_' + str(PERIOD) + '.csv')

    list_anomalies = []
    list_annotations = []

    labels = []
    ports_annot = pd.read_csv(PATH_EVAL + 'eval_total_separated_' + str(PERIOD) + '_' + str(T) + '_' 
        + str(N_MIN) + '_score.csv', sep = ';', index_col = 0)
    print(ports_annot.head(n=20))
    ports = ports_annot.applymap(sign_to_score)
    print(ports.head(n=20))
    ports = ports.loc[(ports > THRESHOLD_ANO).any(axis=1)]

    for index, row in ports.iterrows():
        for i, date in enumerate(dates[N_DAYS:]):
            if row[i] > THRESHOLD_ANO:
                anomalies = []
                annotations = []
                labels.append('port ' + str(index) + '\non ' + date[0:2] + '/' + date[2:])
                for feat in list_features:
                    if feat.attribute != 'nb_packets':
                        evaluation = pd.read_csv(PATH_EVAL + 'eval_' + feat.attribute + '_separated_' + str(PERIOD) + '_' + str(T) + '_' 
                            + str(N_MIN) + '_score.csv', sep = ';')
                        rep = evaluation[evaluation.port == index].loc[:, date]
                        if rep.empty == False:
                            if str(rep.item()) == 'nan':
                                anomalies.append(0)
                                annotations.append(0)
                            else:
                                anomalies.append(get_sum_string(rep.item()))
                                annotations.append(rep.item())
                        else:
                            anomalies.append(0)
                            annotations.append(0)
                list_anomalies.append(anomalies)
                list_annotations.append(annotations)

    columns = [feat.attribute for feat in list_features if feat.attribute != 'nb_packets']
    heatmap = pd.DataFrame(list_anomalies, columns=columns, index = labels)
    heatmap_annot = pd.DataFrame(list_annotations, columns=columns, index = labels)

    data = np.array(heatmap)
    data_annot = np.array(heatmap_annot)

    # Plot
    fig, ax = plt.subplots()
    im = ax.imshow(data, cmap='YlOrRd', aspect=.45)

    ax.set_ylabel('Anomaly ID')
    ax.set_xlabel('Feature')

    ax.set_xticks(np.arange(data.shape[1]))
    ax.set_yticks(np.arange(data.shape[0]))
    ax.set_yticklabels(labels)
    ax.set_xticklabels(['srcDivInd', 'dstDivInd', 'portDivInd', 'meanSize', 'stdSize', 'perSyn'])

    # Rotate the tick labels and set their alignment.
    plt.setp(ax.get_xticklabels(), rotation=20, ha="right", rotation_mode="anchor")

    for edge, spine in ax.spines.items():
        spine.set_visible(False)
    ax.set_xticks(np.arange(data.shape[1]+1)-.5, minor=True)
    ax.set_yticks(np.arange(data.shape[0]+1)-.5, minor=True)
    ax.grid(which="minor", color="w", linestyle='-', linewidth=3)
    ax.tick_params(which="minor", bottom=False, left=False)

    ax.set_yticklabels(labels)
    ax.set_xticklabels(columns)

    # Loop over data dimensions and create text annotations.
    for i in range(0, data.shape[0]):
        for j in range(0, data.shape[1]):
            annot = str(data_annot[i, j]).split(',')
            if len(annot) == 1:
                text = ax.text(j, i, '0',
                        ha="center", va="center", color='black', size=10)
            # 3 cases: two non-zero values, one non-zero value or two zero values
            else:
                if '0' in annot[0]:
                    if '0' in annot[1]:
                        text = ax.text(j, i, '0',
                            ha="center", va="center", color='black', size=10)
                    else:
                        text = ax.text(j, i, annot[1],
                            ha="center", va="center", color=color(annot[1]), size=10)
                else:
                    if '0' in annot[1]:
                        text = ax.text(j, i, annot[0],
                            ha="center", va="center", color=color(annot[0]), size=10)
                    else:
                        text = ax.text(j, i-0.18, annot[0],
                            ha="center", va="center", color=color(annot[0]), size=10)
                        text = ax.text(j, i+0.18, annot[1],
                            ha="center", va="center", color=color(annot[1]), size=10)

    if not os.path.exists(PATH_FIGURES):
        os.mkdir(PATH_FIGURES)
    plt.savefig(PATH_FIGURES + 'heatmap_anomalies_' + str(T) + '_' + str(N_MIN) + '_' + str(PERIOD) + '.png', dpi=600, bbox_inches='tight')

# Choose color of heatmap annotation (black or white) based on the color of the square.
def color(pos):
    color = 'black'
    if int(pos[1:]) > 6:
        color = 'white'
    return color

def main(argv):
    heat_map_scores()
    # heatmap_anomalies()
    return 0

if __name__ == "__main__":
    main(sys.argv)