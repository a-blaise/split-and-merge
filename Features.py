import matplotlib.pyplot as plt
from Settings import *

class Feature:
    def __init__(self, att):
        self.attribute = att
        self.time_vect = []
        self.sub_time_vect = {}
        self.zscores = {}
        self.mzscores = {}
        self.to_write = ''
        self.mse = []
        self.ports = []

    def reset_object(self):
        del self.time_vect[:]
        self.sub_time_vect.clear()
        self.zscores = dict.fromkeys(dates[N_DAYS:], '')
        self.mzscores = dict.fromkeys(dates[N_DAYS:], '')

class Figure(Feature):
    def __init__(self, att, leg):
        Feature.__init__(self, att)
        self.legend = leg
        self.fig, self.ax = plt.subplots()
        self.fig_a, self.ax_a = plt.subplots()
        self.fig_z, self.ax_z = plt.subplots()
        self.fig_z_a, self.ax_z_a = plt.subplots()

    def reset_object(self):
        Feature.reset_object(self)

attributes_legends = dict(nb_packets='Number of packets', src_div_index='Source diversity index', dst_div_index='Destination diversity index', 
    port_div_index='Port diversity index', mean_size='Mean size', std_size='Std size', SYN='Percentage of SYN packets')

list_features = []
for key in attributes_legends.keys():
    list_features.append(Feature(str(key)))

list_figures = []
for key, value in attributes_legends.items():
    list_figures.append(Figure(str(key), value))