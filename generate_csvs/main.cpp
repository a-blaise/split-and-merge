// Copyright 2018 @ Agathe Blaise.

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

#include <tins/tins.h>
#include <iostream>
#include <fstream>

using namespace Tins;

const std::string ROOT_FILE = "/split-and-merge/";

// change this period either to 2016 or 2018
const int period = 2018;

// put these dates if 2018
std::string dates[] = {"1026", "1102", "1109", "1116", "1123", "1130", "1207", "1214", "1221", "1228", "0104", "0111", "0118", "0125", "0201",
    "0208", "0215", "0222", "0301", "0308", "0315", "0322", "0329", "0405", "0412", "0419", "0426", "0503", "0510", "0517", "0524", "0531"};

// put these dates if 2016
// std::string dates[] = {"0331", "0407", "0414", "0421", "0428", "0505", "0512", "0519", "0526", "0602", "0609", "0616", "0622", "0630", 
//   "0707", "0714", "0721", "0728", "0804", "0811", "0818", "0825", "0901", "0908", "0915" ,"0922", "0929", "1006", "1013", "1020"};

const int size_d = sizeof(dates) / sizeof(*dates);
std::ofstream files[size_d];

bool doo_tcp(PDU &pdu, int i) {
  const IP &ip = pdu.rfind_pdu<IP>();
  const TCP &tcp = pdu.rfind_pdu<TCP>();
  files[i] << ip.src_addr() << "," <<
  ip.dst_addr() << "," <<
  pdu.size() << "," <<
  tcp.sport() << "," <<
  tcp.dport() << ",";
  if (tcp.get_flag(TCP::ACK)) {
    if (tcp.get_flag(TCP::SYN)) {
      files[i] << 1 << "," << 0 << "," << 0 << "," << 0 << "," << 0 << "," << 0 << std::endl;
    } else {
        if (tcp.get_flag(TCP::RST)) {
          files[i] << 0 << "," << 1 << "," << 0 << "," << 0 << "," << 0 << "," << 0 << std::endl;
        } else if (tcp.get_flag(TCP::FIN)) {
            files[i] << 0 << "," << 0 << "," << 1 << "," << 0 << "," << 0 << "," << 0 << std::endl;
        } else files[i] << 0 << "," << 0 << "," << 0 << "," << 1 << "," << 0 << "," << 0 << std::endl;
    } 
  } else {
      files[i] << 0 << "," << 0 << "," << 0 << "," << 0 << ","
      << std::to_string(tcp.get_flag(TCP::SYN)) << "," 
      << std::to_string(tcp.get_flag(TCP::RST)) << std::endl;
  }
  return true;
}

int main() {
  int i = 0;
  std::string year = "";
  for (int i = 0; i < size_d; i++) {
    if (period == 2018) {
      if (stoi(dates[i]) > 1000) {
        year = "2017";
      } else {
        year = "2018";
      }
    } else {
      year = "2016";
    }
    std::string csv = ROOT_FILE + "csvs/data_2017" + dates[i] + ".csv";
    files[i].open(csv);
    files[i] << "IP_src,IP_dst,size,port_src,port_dst,SYN+ACK,RST+ACK,FIN+ACK,ACK,SYN,RST" << std::endl;
    std::string pcap = "/Users/agatheblaise/pcaps/2017" + dates[i] + "1400.pcap";
    FileSniffer sniffer(pcap);
    sniffer.sniff_loop([i] (PDU &pdu) -> bool {
      doo_tcp(pdu, i);
      return true;
    });
    files[i].close();
  }
}
