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
import os
from subprocess import call
from settings import *

# Recover pcap files from the MAWI database for all days and unzip them
def recover_pcap_files():
	year = ''
	for date in DATES:
		if PERIOD == 2016:
			if int(date) > 1000:
				year = '2015'
			else:
				year = '2016'

		if PERIOD == 2017:
			if int(date) > 1000:
				year = '2016'
			else:
				year = '2017'

		if PERIOD == 2018:
			if int(date) > 1000:
				year = '2017'
			else:
				year = '2018'
			
		if not os.path.exists(PATH_PCAPS):
			os.mkdir(PATH_PCAPS)
		os.chdir(PATH_PCAPS)
		call(['wget', '-c', 'http://mawi.wide.ad.jp/mawi/samplepoint-F/' + year + '/' + year + date + '1400.pcap.gz'])
		# call(['gunzip', year + date + '1400.pcap.gz'])

def main(argv):
	recover_pcap_files()
	return 0

if __name__ == "__main__":
	main(sys.argv)