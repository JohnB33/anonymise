# anonymise
Matlab code to anonymise DCP log and pcap file. It makes 2 filename requests, one for the DHCP log and the other the pcap file 
and outputs 2 anonymised files with anon added to the filenames just before the file extension.

How it works.
Code scrapes mac addresses from the DHCP log and then replaces the 3 least significant nibbles with a device number,
but leaves the manufacturers part unchanged. It also changes the device name to be Device_xx.

The MAC addresses are then changed in the PCAP file and match the anonymised DHCP log.
