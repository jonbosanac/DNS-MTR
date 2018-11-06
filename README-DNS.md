The DNS Tool
The data comes from a custom DNS tool that does a real-time measurement which looks like a  "dig +trace" in an MTR style curses interface for 8 different hosts at the same time.  Displayed first before the measurement is the record type and TTL.  

usage: ipv6_debug_dns_comparison_tool.py [-h] [--hostname HOSTNAME]
                                         [--resolver RESOLVER]
                                         [--resolverlist RESOLVERLIST]
                                         [--nopoll] [--ipv6]
                                         [--csvfile CSVFILE] [--sample SAMPLE]
                                         target
                                         [addl_targets [addl_targets ...]]

The CSV output:
To generate the CSV data, the command is run in the following way.

$ dns_comparison_tool.py --resolver 8.8.8.8 --csvfile 8.8.8.8-example.csv  \
> images.voonik.com www.nuubit.com nb-br.wal.co
$ head 8.8.8.8-example.csv
"2017-09-16T13:52:03.046797","b.root-servers.net.","k.gtld-servers.net.","ns-1054.awsdns-03.org.","images.voonik.com.revdn.net.","images.voonik.com","","i.root-servers.net.","h.gtld-servers.net.","dns4.p03.nsone.net.","www.nuubit.com.revdn.net.","www.nuubit.com","","g.root-servers.net.","ns5.cctld.co.","pdnswm6.ultradns.co.uk.","nb-br.wal.co.revdn.net.","nb-br.wal.co",""
"2017-09-16T13:52:03.046797","NS","NS","NS","CNAME","","","NS","NS","NS","CNAME","","","NS","NS","NS","CNAME","",""
"2017-09-16T13:52:03.046797",88242,172800,172800,300,"","",13798,172800,172800,360000,"","",135241,172800,7200,300,"",""
"2017-09-16T13:52:05.052691",0.09140586853027344,0.11209583282470703,0.06629705429077148,0.07067084312438965,0.3404695987701416,"",0.042128801345825195,0.04885292053222656,0.07002997398376465,0.10351705551147461,0.264528751373291,"",0.09141182899475098,0.15456485748291016,0.06864404678344727,0.1096189022064209,0.4242396354675293,""
"2017-09-16T13:52:06.058779",0.04862689971923828,0.1598529815673828,0.06502509117126465,0.041822195053100586,0.31532716751098633,"",0.039314985275268555,0.0497899055480957,0.027698993682861328,0.04254889488220215,0.15935277938842773,"",0.03935503959655762,0.16112494468688965,0.042749881744384766,0.033782958984375,0.27701282501220703,""



The initial time stamp has the QUERY, is the TYPE and the TTL.  QUERY, TYPE and TTL items are only printed once.  
The output between each target will need to have a blank column and look like this: ,, 
The goal is to use this as a parity bit in case, for some odd reason, there was an extra hop, without some marker between targets data could get mixed.


