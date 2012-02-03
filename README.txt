
----------------------------------------------
  This is TCR the Test Case Recorder project
----------------------------------------------

It has three big part but only the first part goes to open source.

TCRConvert.java
tcr_convert.properties

These files are still closed.

TCRInit.java          
TCRLogin.java         
TCRLogout.java        
TCRReplay.java        
TCRRead.java          
TCRCompare.java       
TCRFilter.java        
TCRMakeSumma.java     


/**
 * TCRConvert class parsing raw Globus Server Telnet communication's capture data, 
 * made with the tcpdump unix utility.
 *  
 * http://www.tcpdump.org/tcpdump_man.html  (check options -Cwz -r too)
 * 
 * How to record the communication
 * ====================================
 * 
 * Use the following command -> if you want to send the ASCII data -> thru an OS pipe, into a file.  
 * 
 * Use options -K and -z gzip from tcpdump version 4.0.0 only !!!
 * 
 * sudo /usr/sbin/tcpdump -i lan0 -tttt -vKXSs 1514 host r6test2.city.local and port 6201 > r6.capture.txt
 * 
 * Use the following command, if you want to save the raw binary output into fixed sized files/parts.
 * 
 * sudo /usr/sbin/tcpdump -i lan0 -s 1514 -w r6.record.0 -C 10 -z gzip host igrobot.city.local and port 6201
 * 
 * Use the following command to convert a raw binary file/part into an ASCII format file. 
 * Then you have to concat the parts into one big r6.capture.txt file.
 * 
 * sudo /usr/sbin/tcpdump -tttt -vKXS -r r6.capture.bin > r6.capture.txt
 * 
 * 
 * [tcpdump] how to fix the bad checksum problem
 * ------------------------------------------------ 
 * Tuesday, June 17, 2008
 * 
 * If you capture packets using tcpdump directly from the server, your capture file 
 * may contain bad checksums. This is because your OS is currently configured to use 
 * the hardware checksum offloading feature of the NIC. 
 * 
 * When this feature is enabled, expecting the NIC to rewrite the checksums, OS 
 * doesn't bother to fill (nor to reset) in the checksum fields. The problem is that 
 * tcpdump is capturing the packets before the checksums are rewritten by the NIC.
 *                                                                                                                            
 * Use the following command to turn off the checksum offloading before using 
 * tcpdump on ubuntu.
 * 
 * sudo ethtool -K eth0 rx off tx off
 * 
 * On HPUX use the nwmgr command instead
 * ------------------------------------------
 * nwmgr -s -f -c lan0 -A rx_cko=off
 * nwmgr -s -f -c lan0 -A tx_cko=off
 *
 * To check /usr/sbin/nwmgr -A all -c lan0
 *
 *
 * how to collect all override messages only once
 * -------------------------------------------------
 * grep POPUP tcr_convert.log | sort -u 
 *
 * how to collect all invalid version filter message
 * ----------------------------------------------------
 * grep "* Invalid ver" tcr_convert.log | sort -u 
 * 
 * 
 * @author loolek@gmail.com
 */

