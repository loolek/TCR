package org.peter.tcr;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.rmi.RemoteException;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.apache.log4j.Logger;

import org.peter.util.Robot;
import org.peter.util.Tool;

//import hu.fot.util.LoggerUtil;
 
/**
 * This class parsing raw Globus Server Telnet communication's capture data, 
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
public class TCRConvert { // extends PerfGSummarizedScript {

  private static boolean FLAG_NO_PASS_3 = false;
  private static boolean FLAG_ONLY_PASS_3 = true;
  
  private static boolean FLAG_SAVE_LOG = true;
  private static boolean FLAG_LOG_VERBOSE = true;
  private static boolean FLAG_TURN_OFF_LOG4J = true;
  private static boolean FLAG_USE_PORT_NUMBER = true;
  
  private static boolean FLAG_DO_BACKUP = false;
  private static boolean FLAG_DELETE_TEMP = true;
  
  ///////////////////////////////////////////////////////////////////////// 
  // DEVELOPER VIEW OPTIONS

  private static boolean FLAG_SAVE_DROP = true;
  private static boolean FLAG_SAVE_DEV_VIEW = true;

  private static boolean FLAG_SHOW_TAB = false;
  private static boolean FLAG_SHOW_NEWLINE = true;
  private static boolean FLAG_SHOW_UNKNOWN = false;

  ///////////////////////////////////////////////////////////////////////// 
  // FILTER STUFF

  private static String FILE_INPUT = "?";
  private static String FILE_CONFIG = "?";

  private static String FILTER_SERVER = "?";
  private static String FILTER_PORT = "6201";

  private static String FILTER_USER_COPY = "?";
  private static String FILTER_ENVIROMENT = "?";
  private static String FILTER_VERSION_COPY = "?";

  private static List<String> FILTER_USER_LIST = new ArrayList<String>();
  private static List<String> FILTER_CLIENT_LIST = new ArrayList<String>();
  private static List<String> FILTER_VERSION_LIST = new ArrayList<String>();

  /////////////////////////////////////////////////////////////////////////

  private static String FILE_LOG = "tcr_convert.log";
  private static String FILE_ERROR_LOG = "tcr_convert.error.log";
  private static String EXT_ROBOT = ".robot.txt";
  private static String EXT_CAPTURE = ".capture.txt";
  private static String EXT_TCR = ".tcr";
  
  private static String HEADER_SEP = "|";
  private static String DATA_SEP = "·";
  private static String GLOBUS_SEP = "~";

  private String TCRLOOKUP[] = { "COMMITMENT.NO", "LN.PEG.TO.DEPO", "CROSS.REFERENCE",
                                 "SYND.LOAN.REF", "FHB.B.TO.B",     "EMP.LD.ID",        
                                 "FT.REFERENCE",  "COLL.CONT.NO"  
                               };

  /////////////////////////////////////////////////////////////////////////
  // SYSTEM

  private static String PATH;
  private static String SEP = File.separator;
  
  public static String FILE_PROPS = "tcr_convert";
  
  private static int DELIMITER_7E = 0xFE;
  private static int DELIMITER_7F = 0xFF;
  private boolean isAUTODELIMITER = false;
  
  private static long LINE_COUNTER = 0;
  private static long SUMMA_LINE_COUNTER = 0;
  private static long SUMMA_OPEN = 0;
  private static long SUMMA_ERROR = 0;
  private static long SUMMA_COMMIT = 0;
  private static long SUMMA_FAILED = 0;
  private static long SUMMA_MESSAGE = 0;
  private static long SUMMA_TRANSACTION = 0;
  private static long SUMMA_TXN_DROP = 0;

  private static String FILE_OUTPUT = null;
  private static String FILE_BACKUP = null;
  private static String FILE_DEVEL = null;
  private static String FILE_DROP = null;

  private long startTime = 0;

  private boolean inLOGIN = false;
  private boolean inPASSWORD = false;
  private boolean isFILTER = false;
  private boolean inSECONDLEG = false;
  private boolean inSPECIALSECONDLEG = false;
  private boolean liveNotChanged = false;
  private static boolean isFatal = false;
  
  private static int COMMIT_NOP = 0;
  private static int COMMIT_BEGIN = 1;
  private static int COMMIT_SECOND_LEG = 2;
  private static int COMMIT_TXN_COMPLETE = 3;
  private static int COMMIT_TXN_VERIFIED = 4;
  private static int COMMIT_TXN_FAILED = 5;
  private static int COMMIT_PLEASE_REKEY = 6;
  private static int COMMIT_OVERRIDE = 7;
  private static int COMMIT_CONTINUE = 8;
  
  private int inCOMMIT = COMMIT_NOP;
  
  private Map<String, Boolean> inECHO = new HashMap<String, Boolean>();

  private List<String> SERVERS = new ArrayList<String>();
  private List<String> uLOGINS = new ArrayList<String>();
  private List<String> gLOGINS = new ArrayList<String>();
  private List<String> fileList = new ArrayList<String>();
  private List<String> dropList = new ArrayList<String>();
  private List<String> uniqueSotList = new ArrayList<String>();
  
  private Map<String, String> TELLERS = new HashMap<String, String>();
  private Map<String, String> FIELDS = new HashMap<String, String>();

  private String HEADER, HEADER1, HEADER2, LOG_HEADER = "";
  private String ENV, DATE, MODE, SIGNO, USER, PASSWORD, TRID, TRID_COPY, OTRID;
  private String VERSION, VERSION_HEAD, VERSION_FULL, VERSION_LAST, VERSION_SECOND_LEG;
  private String CLIENT, TIME, FROM, TO, LENGTH, ACK, DATA, FIELD, VALUE, TYPE, FLAGS, KEY, UNIX, TMP;

  private List<Object> CONTENT = new ArrayList<Object>();
  private List<String> RAWDATA = new ArrayList<String>();
  private List<Integer> RAWCONTENT = new ArrayList<Integer>();

  private static String STR_LINE = Tool.makeSeparator(70, '-');
  private static String STR_PART = Tool.makeSeparator(70, '=');
  private static String STR_WARN = Tool.makeSeparator(70, '~');

  private String[] modeList = {"S", "I", "A", "D", "R", "C", "V", "L"};

  private static ResourceBundle PROPS;
  
  private static Logger logger; // = LoggerUtil.getMyLogger();

  ////////////////////////////////////////////////////////////////////////////////////////////////////

/*
  public TCRConvert(VirtualUser vu) throws RemoteException, ScriptStopped { 
    super(vu); 
  }
  
  @Override
  public void runScriptAction() throws RemoteException, ScriptStopped {
  
    try {
      LoggerUtil.removeFileAppender(false);
     
      doPass1();
      doPass2();
      doPass3();
  
    } catch (Exception e) { 
      fatalError(0, e); 
      return;
    }
  }
*/

  private void message(String message) throws RemoteException {

    if (cityFilter(false))
      return;
    
    if (Tool.isNull(message))
      return;

    if (message.startsWith("ERROR ") || message.startsWith("FATAL ERROR ") || (contains(message, "TXN CANCELLED") && liveNotChanged == false)) {
      logger.error(message);
      //Tool.err(message);
      
      if (message.startsWith("ERROR - BAD CHECK SUM"))
        return;
      
      if (message.startsWith("ERROR - Broken"))
        return;
      
      SUMMA_ERROR++;
      
      appendErrorLog(message);
    
    } else if (message.startsWith("WARN") || message.startsWith("*** TXN")) {
      logger.warn(message);
      //Tool.out(message);

    } else {
      logger.info(message);
      //Tool.out(message);

      if (contains(message, "LIVE RECORD NOT CHANGED") || contains(message, "AZ ADATOKBAN VÁLTOZÁS NEM TÖRTÉNT")) {
        liveNotChanged = true;
      }
    }
    
    appendLog(message);
    
    SUMMA_MESSAGE++;
  }

  private void _message_(String message) throws RemoteException {

    message(STR_LINE);
    message(message);
    message(STR_LINE);
  }

  private void message_(String message) throws RemoteException {

    message(STR_PART);
    message(message);
    message(STR_PART);
  }

  private void _message(String message) throws RemoteException {

    message(STR_PART);
    message(message);
    message(STR_LINE);
  }
  
  private void appendErrorLog(String message) {

    try {     
      if (LOG_HEADER.length() != 0) {
        Tool.append(FILE_ERROR_LOG, STR_PART + "\r\n" + LOG_HEADER + "\r\n" + STR_PART + "\r\n");
        LOG_HEADER = "";
      }
      
      Tool.append(FILE_ERROR_LOG, message + "\r\n");
      
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void appendLog(String message) {

    if (FLAG_SAVE_LOG == false)
      return;
    
    try {
      Tool.append(FILE_LOG, message + "\r\n");
      
    } catch (IOException e) {
      e.printStackTrace();
    }
  }

  private void fatalError(int pass, Exception e) {

    try {
      message(STR_WARN);
      message("FATAL ERROR - at pass " + pass + ", line " + LINE_COUNTER);
      message(STR_WARN);
      message("");

      appendLog(TMP = Tool.getStackTrace(e));
      appendErrorLog(TMP);
      
      isFatal = true;

    } catch (RemoteException e1) {}

    e.printStackTrace();
  }
  
  // MAGYARORSZ'·C1·'G
  private static String hungarian(String data) {
    
    data = Tool.replace(data, "·C1·", "·'Á'·");
    data = Tool.replace(data, "·C9·", "·'É'·");
    data = Tool.replace(data, "·D3·", "·'Ó'·");
    data = Tool.replace(data, "·D5·", "·'Õ'·");
    data = Tool.replace(data, "·D6·", "·'Ö'·");
    data = Tool.replace(data, "·DB·", "·'Û'·");
    data = Tool.replace(data, "·DC·", "·'Ü'·");
    data = Tool.replace(data, "·CD·", "·'Í'·");

    data = Tool.replace(data, "·E1·", "·'á'·");
    data = Tool.replace(data, "·E9·", "·'é'·");
    data = Tool.replace(data, "·F3·", "·'ó'·");
    data = Tool.replace(data, "·F5·", "·'õ'·");
    data = Tool.replace(data, "·F6·", "·'ö'·");
    data = Tool.replace(data, "·FB·", "·'û'·");
    data = Tool.replace(data, "·FC·", "·'ü'·");
    data = Tool.replace(data, "·ED·", "·'í'·");

    data = Tool.replace(data, "'·'", "");
    
    return (data);
  }
  
  //////////////////////////////////////////////////////////////////////
  // RAW TCPDUMP ASCII DATA from v4.0.0

  /*
    2011-02-22 16:37:56.374942 IP (tos 0x0, ttl 126, id 8747, offset 0, flags [DF], proto TCP (6), length 48)
        xp2967.city.local.4237 > r6dev.city.local.6201: Flags [S], seq 2097240021, win 64512, options [mss 1460,nop,nop,sackOK], length 0
          0x0000:  4500 0030 222b 4000 7e06 26cb 0a08 9610  E..0"+@.~.&.....
          0x0010:  0ad9 08e1 108d 1839 7d01 57d5 0000 0000  .......9}.W.....
          0x0020:  7002 fc00 d5af 0000 0204 05b4 0101 0402  p...............
    2011-02-22 16:37:56.375013 IP (tos 0x0, ttl 64, id 40381, offset 0, flags [DF], proto TCP (6), length 48)
        r6dev.city.local.6201 > xp2967.city.local.4237: Flags [S.], seq 1641291674, ack 2097240022, win 32768, options [mss 1460,nop,nop,sackOK], length 0
          0x0000:  4500 0030 9dbd 4000 4006 e938 0ad9 08e1  E..0..@.@..8....
          0x0010:  0a08 9610 1839 108d 61d4 1f9a 7d01 57d6  .....9..a...}.W.
          0x0020:  7012 8000 b3f4 0000 0204 05b4 0101 0402  p...............
  */

  private void doPass1() {

    int index;
    String line;

    MODE = "";
    LOG_HEADER = "";

    if (isFatal)
      return;

    if (FLAG_TURN_OFF_LOG4J) {
//    LoggerUtil.removeFileAppender(!Tool.isWindowsPlatform());
    }
    
    try {
          
      if (FLAG_ONLY_PASS_3) {
        message (STR_PART);
        message("SKIP PASS #1");
        return;
      }
      
      message_("PARSER PASS #1");
      
      // If contains the full path from args param then leave it.
      if (FILE_INPUT.indexOf(SEP) == -1) {
        FILE_INPUT = PATH + SEP + FILE_INPUT;
      }
      
      BufferedReader br = Tool.initFileReader(FILE_INPUT);

      while (true) {
        LINE_COUNTER++;

        if ((line = Tool.nextLine(br)) == null) {
          // Parse the last one, then break.
          parsePass1();
          appendPass1();
          break;
        }

        
        if (line.length() == 0)
          continue;

        // HEADER 
        if (line.startsWith("20")) {  // 2011-02-23
          // If not the first header
          if (RAWDATA.size() > 0) {
            parsePass1();
            appendPass1();
          }

          HEADER1 = line;
          LINE_COUNTER++;
/*
  Older tcpdump versions like 3.9.5 saving -> the two header line in one line !!!

  2011-05-19 14:11:25.677108 IP (tos 0x0, ttl 64, id 21994, offset 0, flags [DF], proto TCP (6), length 116)
    igfot.city.local.glist > xp2358.city.local.1274: Flags [P.], ack 3163381115, win 32768, length 76
 
  2011-05-19 14:10:24.453216 IP (tos 0x0, ttl 126, id 44156, offset 0, flags [DF], proto: TCP (6), length: 40) xp2358.city.local.1217 > r6test2.glist: ., cksum 0x8898 (correct), ack 1471624536 win 40792
*/
          try {
            if (contains(HEADER1, " > ")) {
              // v3.9.5
              if ((index = HEADER1.indexOf("length:")) != -1) {
                if ((index = HEADER1.indexOf(')', index)) != -1) {
                  HEADER2 = HEADER1.substring(index + 2);
                  HEADER1 = HEADER1.substring(0, index + 1);
                  parseHeader_V3();
                }
              }
            } else {
              // v4.0.0
              if ((HEADER2 = Tool.nextLine(br)) == null) {
                message(STR_WARN);
                message("FATAL ERROR - 'BROKEN EOF' EXIT PASS! in line " + LINE_COUNTER);
                isFatal = true;
                break;
              } else {
                parseHeader_V4();
              }
            }

          } catch (Exception e) {
            message(STR_WARN);
            message("FATAL ERROR - 'BROKEN EOF' EXIT PASS!! in line " + LINE_COUNTER + " - '" + e.getMessage() + "'");
            isFatal = true;
            e.printStackTrace();
            break;
          }

          RAWDATA.clear();
          continue;

        // DATA
        } else {
          // Must start with a TAB character
          if (line.length() > 10 && line.charAt(0) == 9)
            RAWDATA.add(line);
          else {
            message(STR_WARN);
            message("FATAL ERROR - 'BROKEN EOF' EXIT PASS!!! in line " + LINE_COUNTER);
            isFatal = true;
            break; 
          }
        }
      }

      Tool.closeFileReader(br);

      message(STR_LINE);
      message("SUCCESS - saved " + SUMMA_TRANSACTION + " files (parsed " + LINE_COUNTER + " lines)");

    } catch (Exception e) {
      // PANIC
      fatalError(1, e);
    }
  }

/*
  Older tcpdump versions like 3.9.5 saving the header in one line !!!
  
  2011-05-19 14:10:24.453216 IP (tos 0x0, ttl 126, id 44156, offset 0, flags [DF], proto: TCP (6), length: 40) xp2358.city.local.1217 > r6test2.glist: ., cksum 0x8898 (correct), ack 1471624536 win 40792
  
  2011-05-25 16:38:53.624670 IP (tos 0x0, ttl 126, id 30430, offset 0, flags [DF], proto: TCP (6), length: 70) xp3214.city.local.nfs > r6test2.4212719610: reply ERR 30
*/
  private void parseHeader_V3() throws RemoteException {

    HEADER2 = Tool.replace(HEADER2, ".glist", "." + FILTER_PORT);

    String[] dim1 = HEADER1.split(" ", -1);
    String[] dim2 = HEADER2.split(" ", -1);

    //Tool.out(">> " + dim2.length + "\r\n" + Tool.printString(dim2));

    if (dim1.length < 2 || dim2.length < 5 || dim2[1].equals(">") == false)
      throw new RuntimeException("Invalid TCP/IP header! '" + HEADER2 + "'");

    DATE = dim1[0];
    TIME = dim1[1];
    FROM = dim2[0];
    // Cut last ':' char
    TO = dim2[2].substring(0, dim2[2].length() - 1);

    showCaptureTime(TIME);
    
    for (int i = 0; i < dim1.length; i++) {
      if (dim1[i].equals("length:")) {
        // Cut last ')' char
        LENGTH = dim1[i + 1].substring(0, dim1[i + 1].length() - 1);
        break;
      }
    }
  
    if (LENGTH.equals(""))
      throw new RuntimeException("Can't find length value!");

    // We need to subtract the header size here.
    LENGTH = "" + (Integer.parseInt(LENGTH) - 40);
    
    // Get ack
    if (dim2.length > 8 && dim2[7].equals("ack"))
      ACK = dim2[8];
    else if (dim2.length > 9 && dim2[8].equals("ack"))
      ACK = dim2[9];
    else {
      ACK = "";
    }
    
    if (HEADER2.indexOf("(correct)") == -1)
      message("ERROR - BAD CHECK SUM! - at pass 1, line " + LINE_COUNTER);
    
    makeOutputName();
  }

/*
  2011-02-22 16:37:56.375013 IP (tos 0x0, ttl 64, id 40381, offset 0, flags [DF], proto TCP (6), length 48)
    r6dev.city.local.6201 > xp2967.city.local.4237: Flags [S.], seq 1641291674, ack 2097240022, win 32768, options [mss 1460,nop,nop,sackOK], length 0
    
  2011-02-25 14:20:54.514221 IP (tos 0x0, ttl 64, id 38341, offset 0, flags [DF], proto TCP (6), length 6280, bad cksum eb84 (->d8d8)!)
    r6dev.city.local.6201 > 10.8.150.16.1369: Flags [P.], ack 860579885, win 32768, length 6240
*/
  private void parseHeader_V4() throws RemoteException {

    HEADER2 = Tool.replace(HEADER2, ".glist", "." + FILTER_PORT);

    String[] dim1 = HEADER1.split(" ", -1);
    String[] dim2 = HEADER2.split(" ", -1);

    // Tool.out(">> " + Tool.printString(dim2));

    if (dim1.length < 2 || dim2.length < 13 || dim2[5].equals(">") == false)
      throw new RuntimeException("Invalid TCP/IP header! '" + HEADER2 + "'");

    DATE = dim1[0];
    TIME = dim1[1];
    FROM = dim2[4];
    // Cut last ':' char
    TO = dim2[6].substring(0, dim2[6].length() - 1);

    showCaptureTime(TIME);
    
    for (int i = 0; i < dim2.length; i++) {
      if (dim2[i].equals("length")) {
        LENGTH = dim2[i + 1];
        break;
      }
    }
    
    if (LENGTH.equals(""))
      throw new RuntimeException("Can't find length value!");

    // Get ack and cut last ',' char
    if (dim2[9].equals("ack"))
      ACK = dim2[10].substring(0, dim2[10].length() - 1);
    else if (dim2[11].equals("ack"))
      ACK = dim2[12].substring(0, dim2[12].length() - 1);
    else
      ACK = "";

    FLAGS = dim2[8].substring(0, dim2[8].length() - 1);

    if (contains(HEADER1, "bad cksum"))
      message("ERROR - BAD CHECK SUM! - at pass 1, line " + LINE_COUNTER);
    
    makeOutputName();
  }

  private String TIME_MARK = "00:00:00";
  
  private void showCaptureTime(String TIME) throws RemoteException {
  
    // 14:10:24.453216
    if (TIME_MARK.substring(0,4).equals(TIME.substring(0,4)) == false) {
      TIME_MARK = TIME;
      message("CAPTURE TIME - '" + TIME_MARK.substring(0,5) + "'");
    }
  }
  
  private void makeOutputName() throws RemoteException {

    if (TO.startsWith(FILTER_SERVER)) {
      if (FLAG_USE_PORT_NUMBER)
        KEY = FROM + EXT_CAPTURE;
      else
        KEY = FROM.substring(0, FROM.lastIndexOf(".")) + EXT_CAPTURE;
      
    } else {
      
      if (FROM.startsWith(FILTER_SERVER)) {
        if (FLAG_USE_PORT_NUMBER)
          KEY = TO + EXT_CAPTURE;
        else
          KEY = TO.substring(0, TO.lastIndexOf(".")) + EXT_CAPTURE;

      // Unknown server name!
      } else {
        if (FROM.endsWith("." + FILTER_PORT))
          KEY = FROM;
        else
          KEY = TO;
        
        if (SERVERS.contains(KEY) == false) {
          SERVERS.add(KEY);
          message("WARNING - Foreign server! '" + KEY + "'");
        }
          
        KEY = null;
        return;
      }
    }

    KEY = KEY.toLowerCase();

    if (Tool.contains(FILTER_CLIENT_LIST, KEY)) {
      if (dropList.contains(KEY) == false) {
        message("*** DROP CLIENT *** " + KEY.substring(0, KEY.length() - EXT_CAPTURE.length()));
        dropList.add(KEY);
      }

      KEY = null;
      return;
    }

    // Make absolute file name
    FILE_OUTPUT = PATH + SEP + KEY;

    if (fileList.contains(KEY) == false) {
      // First time
      message("OUTPUT FILE '" + KEY + "'");
      fileList.add(KEY);
      inECHO.put(KEY, false);
      Tool.delete(FILE_OUTPUT, false);
      SUMMA_TRANSACTION++;
    }
  }

  /*
     0x0000:  4500 003c 944a 4000 7e06 b49f 0a08 9610  E..<.J@.~.......
     0x0010:  0ad9 08e1 123c 1839 689d cce8 6ce7 657e  .....<.9h...l.e~
     0x0020:  5018 fbb3 a711 0000 fffe 03ff fc1f fffc  P...............
     0x0030:  21ff fc01 7532 3030 3034 330d            !...u200043.
  */
  private void parsePass1() {

    String part;

    if (LENGTH.equals("0") == false) {
      // Cut the header's first (32 + 8 bytes)
      part = RAWDATA.get(2);
      DATA = part.substring(30, 51) + "\r\n";

      for (int i = 3; i < RAWDATA.size(); i++) {
        part = RAWDATA.get(i);
        part = part.substring(10, 51) + "\r\n";
        DATA += part;
      }

      parseData();

    } else {
      // No data
      DATA = "";
    }
  }

  // Fill up RAWCONTENT<Intger> list
  private void parseData() {

    String n1, n2;

    int len = Integer.parseInt(LENGTH);
    String[] dim = Tool.replace(DATA, "\r\n", "").split(" ", -1);

    RAWCONTENT.clear();

    for (int i = 0; i < dim.length; i++) {

      if (dim[i].length() == 0)
        continue;

      if (dim[i].length() == 2) {
        n1 = dim[i].substring(0, 2);
        n2 = "";
        RAWCONTENT.add(Integer.parseInt(n1, 16));
        if (RAWCONTENT.size() == len)
          break;
      }

      if (dim[i].length() == 4) {
        n1 = dim[i].substring(0, 2);
        RAWCONTENT.add(Integer.parseInt(n1, 16));
        if (RAWCONTENT.size() == len)
          break;
      }

      if (dim[i].length() == 4) {
        n2 = dim[i].substring(2);
        RAWCONTENT.add(Integer.parseInt(n2, 16));
        if (RAWCONTENT.size() == len)
          break;
      }
    }
  }

  private void appendPass1() throws IOException {

    int len;
    String data;

    // Filter out unknown server name packets!!!
    if (KEY == null)
      return;
    
    // Filter out zero size packets
    if ((len = Integer.parseInt(LENGTH)) > 0) {
      // Filter out server's SOT echo packets
      if (len == 1 && inECHO.get(KEY))
        return;
      else
        inECHO.put(KEY, false);

      data = printContent(RAWCONTENT);

      if (contains(data, "'&SOT&"))
        inECHO.put(KEY, true);

      // HEADER
      Tool.append(FILE_OUTPUT, DATE + HEADER_SEP + TIME + HEADER_SEP + FROM + HEADER_SEP + TO + HEADER_SEP + ACK + HEADER_SEP + LENGTH + HEADER_SEP + "\r\n"); // + FLAGS);

      // DATA
      Tool.append(FILE_OUTPUT, data + "\r\n", false);
    }
  }

  private String printContent(List<Integer> list) {

    boolean isString = false;

    StringBuilder sb = new StringBuilder();

    for (int i = 0; i < list.size(); i++) {
      int c = list.get(i);

      // Printable character

      if (c > 31 && c < 123) {
        if (isString == false) {
          if (i != 0)
            sb.append(DATA_SEP);

          sb.append("'");
        }

        char ch = (char) c;
        if (ch == '\'')
          sb.append("\\");

        sb.append(ch);
        isString = true;

        // Hexa number
      } else {
        if (isString)
          sb.append("'");

        if (i != 0)
          sb.append(DATA_SEP);

        sb.append(String.format("%02X", c));
        isString = false;
      }
    }

    if (isString)
      sb.append("'");

    return (sb.toString());
  }
  
/*
  2011-03-03|17:47:56.719134|SRV|12|
  [...·]0D·0A·'Password: '
  2011-03-03|17:47:57.820145|CLI|8|
  'notata'·0D[·0A]
*/
  private String changePassword(String data) throws RemoteException {

    if (uLOGINS.contains(USER) == false) {
      uLOGINS.add(USER);
      
      UNIX = data.substring(0, data.indexOf("0D"));
      UNIX = Tool.replace(UNIX, DATA_SEP, "");
      UNIX = Tool.replace(UNIX, "''", "'");

      if (UNIX.charAt(0) == '\'')
        UNIX = UNIX.substring(1, UNIX.length() - 1);

      if (USER != null && USER.length() != 0) {
        if (USER.charAt(0) == '\'')
          USER = USER.substring(1, USER.length() - 1);
      }

      message("UNIX PASSWORD RESET '" + USER + "'");
    }
    
    return ("'123456'" + DATA_SEP + "0D");
  }

  private void setFilterFlags(String data) {
 
    if (contains(data, "'Password: '")) {
      inPASSWORD = true;
      UNIX = "";
    }

    if (contains(data, "'login: '")) {
      inLOGIN = true;
      USER = "";
    }
    
    if (contains(data, "'Login incorrect'")) {
      UNIX = "";
    }   
  }

  ///////////////////////////////////////////////////////////////////
  // PASS #2
  ///////////////////////////////////////////////////////////////////

  private void doPass2() {

    if (isFatal)
      return;

    SUMMA_TRANSACTION = 0;
    SUMMA_LINE_COUNTER = 0;

    try {

      if (FLAG_ONLY_PASS_3) {
        message("SKIP PASS #2");
        return;
      }

      message_("PARSER PASS #2 - " + Tool.getDate("HH:mm:ss"));

      for (int i = 0; i < fileList.size(); i++) {
        // Process a .capture.txt input file
        KEY = fileList.get(i);
        message("INPUT FILE '" + KEY + "'");
        FILE_INPUT = PATH + SEP + KEY;
        FILE_OUTPUT = Tool.replace(FILE_INPUT, EXT_CAPTURE, EXT_ROBOT);
        Tool.delete(new File(FILE_OUTPUT), FLAG_DO_BACKUP);
        SUMMA_TRANSACTION++;
        
        parsePass2(FILE_INPUT);
        
        if (FLAG_DELETE_TEMP) {
          Tool.delete(FILE_INPUT, false);
        }
      }

      message(STR_LINE);
      message("SUCCESS - saved " + SUMMA_TRANSACTION + " files (parsed " + SUMMA_LINE_COUNTER + " lines)");

    } catch (Exception e) {
      // PANIC
      fatalError(2, e);
    }
  }

  /*
    2011-02-22|17:00:10.688684|CLI|54|
    '&SOT&46'·FE·'CITY.LOG.FILE.VIEW_HU0010001_PH.OFSUSER.1&EOT&'·0D
    2011-02-22|17:00:10.690493|SRV|32|
    '&START&46'·FE·'123'·FE·'CITY.MQ.FILE.VIEW'·FF·FF
  */
  private void parsePass2(String fileName) throws IOException {

    long len;
    
    if (new File(fileName).exists() == false) {
      TMP = fileName.substring(fileName.lastIndexOf(SEP) + 1);
      message("WARN - MISSING INPUT FILE! '" + TMP + "'");
      return;
    }
    
    BufferedReader br = Tool.initFileReader(fileName);

    uLOGINS.clear();

    ACK = DATA = "";
    LINE_COUNTER = len = 0;

    while (true) {

      if ((HEADER = Tool.nextLine(br)) == null) {
        // Save the last one
        DATA = Tool.replace(DATA, "'·'", "");
        appendPass2(HEADER1, DATA, len);
        break;
      }

      String[] dim = HEADER.split("[" + HEADER_SEP + "]", -1);

      if (dim.length < 6)
        throw new RuntimeException("FATAL ERROR - Invalid header!");

      if ((TMP = Tool.nextLine(br)) == null)
        throw new RuntimeException("FATAL ERROR - Missing content line!");

      LINE_COUNTER += 2;
      SUMMA_LINE_COUNTER += 2;

      // Merge packets !!!
      if (ACK.equals(dim[4])) {
        DATA = DATA + DATA_SEP + TMP;
        len = len + Integer.parseInt(dim[5]);

      // New packet
      } else {
        ACK = dim[4];

        // OUTPUT
        if (DATA.equals("") == false) {
          DATA = Tool.replace(DATA, "'·'", "");
          appendPass2(HEADER1, DATA, len);
          
          // Begin unix login
          //if (DATA.equals("FF·FD·'$'"))

          // Open Desktop
          //if (contains(DATA, "'&SOT&33'"))
        }

        HEADER1 = dim[0] + HEADER_SEP + dim[1] + HEADER_SEP + (dim[2].startsWith(FILTER_SERVER) ? "SRV" : "CLI") + HEADER_SEP;
        DATA = TMP;
        
        len = Integer.parseInt(dim[5]);
      }
    }

    Tool.closeFileReader(br);
  }

  private void appendPass2(String header, String data, long len) throws IOException {
    
    int index;
    String part1, part2;
    
    if (inPASSWORD) {
      inPASSWORD = false;
      data = changePassword(data);
    }
    
    if (inLOGIN) {
      // Collect the parts
      if (contains(header, "CLI")) {
        if (data.startsWith("'") && data.endsWith("'")) { // && data.equals("'!'") == false) {
          USER = USER + data.substring(1, data.length() - 1);
          return;
          
        } else {
          // FF·FC·'!'
          // FF·FC·01
          if (data.startsWith("F"))
            return;
        }
        
        // 't''r''e''f''i'0D·0A
        if (data.startsWith("0D")) {
          inLOGIN = false;
          USER = "'" + USER + "'";
          data = USER + DATA_SEP + "0D";

        // FF·FD·01·FF·FE·03·FF·FC·1F·FF·FC·'!'·FF·FC·01·'u200043'·0D
        } else {
          if (contains(data, "·0D")) {
            inLOGIN = false;
            USER = USER + data;
            
            if ((USER = Robot.getLastString(parseContent(USER))) != null)
                data = "'" + USER + "'" + DATA_SEP + "0D" + DATA_SEP + "0A";
            
          // Still collecting
          } else
            return;
        }
      } else {
        // Drop server packets in login state
        setFilterFlags(data);
        return;
      }
    }
    
    // Must be first!
    data = hungarian(data);
    
    // Make sure to every &START& MARK be standalone
    if ((index = data.indexOf("&START&")) != -1) {
      data = Tool.replace(data, "&END&&START&", "&END&'" + DATA_SEP + "'&START&");
      
      while (true) {
        // 1B·'[2;1H Internal Payment Order'·1B·'[3;1H &START&7'·7E·'27844'·7E· ... ·1B·'[2;2H&START&6'·7E·'1'·7E·'S&END&'
        if (data.charAt(index - 1) != '\'') {
          part1 = data.substring(0, index);
          part2 = data.substring(index);
          data = part1 + "'" + DATA_SEP + "'" + part2; 
        }
        
        if ((index = data.indexOf("&START&", index + 3)) == -1)
          break;
      }
    }

    // Make sure to every &END& mark be standalone
    if ((index = data.indexOf("&END&")) != -1) {
      
      while (true) {
        // '&START&6'·7E·'1'·7E·'SEND&'
        if (data.charAt(index - 1) != '\'') {
          part1 = data.substring(0, index);
          part2 = data.substring(index);
          data = part1 + "'" + DATA_SEP + "'" + part2; 
        }
        
        if ((index = data.indexOf("&END&", index + 3)) == -1)
          break;
      }
    }

    // Make sure to every &EOT& mark be standalone
    if ((index = data.indexOf("&EOT&")) != -1 && data.charAt(index - 1) != '\'') {
      data = Tool.replace(data, "&EOT&'", "'" + DATA_SEP + "'&EOT&'");
    }
    
    if ((data = customContentFilter(data)) == null)
      return;

    setFilterFlags(data);
    
    Tool.append(FILE_OUTPUT, header + len + HEADER_SEP + "\r\n");
    Tool.append(FILE_OUTPUT, data + "\r\n", false);
  }

  ///////////////////////////////////////////////////////////////////
  // PASS #3
  ///////////////////////////////////////////////////////////////////

  private void doPass3() {

    if (isFatal) {
      doStat();
      return;
    }
    
    if (FLAG_NO_PASS_3) {
      if (FLAG_TURN_OFF_LOG4J) {
//        LoggerUtil.addDefaultFileAppender();
      }
      doStat();
      return;
    }

    isFILTER = true;
    
    FIELDS.clear();
    FILE_OUTPUT = FILE_BACKUP = "";
    
    SUMMA_COMMIT = 0;
    SUMMA_TRANSACTION = 0;
    SUMMA_LINE_COUNTER = 0;
    
    try {

      if (FLAG_ONLY_PASS_3) {
        // Get *.robot.txt files
        String[] files = Tool.listDir(PATH, EXT_ROBOT);
        
        if (files == null)
          throw new RuntimeException("We need '*" + EXT_ROBOT + "' input files! Turn on pass 2!");
        
        fileList = new ArrayList<String>(files.length);
        for (int i = 0; i < files.length; i++) {
          // This trick skip marked debug files
          if (!files[i].startsWith("#"))
            fileList.add(Tool.replace(files[i], EXT_ROBOT, EXT_CAPTURE));
        }
      }

      message_("PARSER PASS #3 - " + Tool.getDate("HH:mm:ss"));

//    PROPS = Tool.loadProperties(PATH + SEP + FILE_PROPS);
      PROPS = Tool.loadResource("org.peter.tcr." + FILE_PROPS);

      for (int i = 0; i < fileList.size(); i++) {
        // Process an input file
        FILE_INPUT = Tool.replace((KEY = fileList.get(i)), EXT_CAPTURE, EXT_ROBOT);
        if (i != 0)
          message(STR_LINE);
        
        message("INPUT FILE '" + FILE_INPUT + "'");
        // Make full path
        FILE_INPUT = PATH + SEP + FILE_INPUT;

        FILE_DEVEL = Tool.replace(FILE_INPUT, EXT_ROBOT, ".devel.txt");
        Tool.delete(new File(FILE_DEVEL), false);

        FILE_DROP = Tool.replace(FILE_INPUT, EXT_ROBOT, ".drop.txt");
        Tool.delete(new File(FILE_DROP), false);

        parsePass3(FILE_INPUT);
      }

      // No user filter from this point 
      isFILTER = false;
      
      double time = Tool.elapsed(startTime);
      
      if (time > 60)
        TIME = String.format("%.2f", time / 60) + " min";
      else
        TIME = String.format("%.2f", time) + " sec";

      // TM log to file again
      if (FLAG_TURN_OFF_LOG4J) {
//      LoggerUtil.addDefaultFileAppender();
      }
      
      message(STR_PART);
      message(TMP = "SUCCESS - parsed " + SUMMA_LINE_COUNTER + " lines (" + SUMMA_OPEN + " open) (" + SUMMA_COMMIT + " commit) (" + SUMMA_ERROR + " error)");

      doStat();
      
      appendErrorLog(STR_LINE);
      appendErrorLog(TMP);
      appendErrorLog(STR_LINE);
      
    } catch (Exception e) {
      // PANIC
      fatalError(3, e);
    }
  }

  private void doStat() {

    double time = Tool.elapsed(startTime);

    try {
      
      if (SUMMA_TRANSACTION == 0) {
        _message_("NO SUCCESSFUL TRANSACTION");
        return;
      }
    
      if (time > 60)
        TIME = String.format("%.2f", time / 60) + " min";
      else
        TIME = String.format("%.2f", time) + " sec";

      message(STR_LINE);
      message("SUCCESSFUL TRANSACTIONS - (" + SUMMA_TRANSACTION + " files)");
      message("TXN DROP TRANSACTIONS - (" + SUMMA_TXN_DROP + ")");
      message(STR_LINE);
      message("ELAPSED TIME - " + TIME + " (log size " + SUMMA_MESSAGE + " lines)");
      message(STR_PART);

      //System.out.println("**** " + Tool.printHashMap((HashMap) FIELDS, true));
      
    } catch (RemoteException e) {
    }
  }

  /*
  2011-03-04|14:19:38.990023|CLI|14|   <- Begin handshake!
  '&SOT&99p'·'&EOT&'·0D
  2011-03-04|14:19:38.990418|SRV|59|
  '&START&99'·FE·'41'·FE·FE·FE·'3,tc'·FE·'04 MAR 2011 14:19'·FE·'g15.0.00'·FE·'r06.004&END&'
*/
  private void parsePass3(String fileName) throws IOException {

    int index;

    if (new File(fileName).exists() == false) {
      TMP = fileName.substring(fileName.lastIndexOf(SEP) + 1);
      message("WARN - MISSING INPUT FILE! '" + TMP + "'");
      return;
    }

    BufferedReader br = Tool.initFileReader(fileName);

    ENV = "";
    VALUE = "";
    VERSION_FULL = "";    
    LINE_COUNTER = 0;
    
    resetOpenState();
    
    gLOGINS.clear();

    while (true) {

      if ((HEADER = Tool.nextLine(br)) == null) {
        // Save the last one
        break;
      }

      if ((DATA = Tool.nextLine(br)) == null)
        throw new RuntimeException("FATAL ERROR - Missing content line!");

      LINE_COUNTER += 2;
      SUMMA_LINE_COUNTER += 2;

      if (HEADER.length() == 0)
        continue;
      
      String[] dim = HEADER.split("[" + HEADER_SEP + "]", -1);

      if (dim.length < 3) {
        throw new RuntimeException("FATAL ERROR - Invalid header! " + Tool.printString(dim));
      }

      // 2011-02-25|14:23:24.030563|SRV|191|
      HEADER = dim[1] + (dim[2].equals("SRV") ? "   " : " > ");
      
      if ((index = DATA.indexOf("&SOT&99p DELIMITERS")) != -1) {
        // '&SOT&99p DELIMITERS127,126,125,124,123,' '&EOT&' 0D
        TMP = DATA.substring(index + 19, index + 38);
        if (TMP.startsWith("127")) {
          DELIMITER_7E = 0x7E;
          DELIMITER_7F = 0x7F;
        } else {
          DELIMITER_7E = 0xFE;
          DELIMITER_7F = 0xFF;
          message(STR_LINE);
        }
        
        message("DELIMITERS '" + TMP + "'");
      }
      
      parseContent(DATA);

      // Drop packet if size == 1
      if (CONTENT.size() == 1) {
        if (CONTENT.get(0) instanceof String){
          TMP = ((String) CONTENT.get(0));
          if (TMP.length() == 1 || (TMP.length() == 2 && TMP.charAt(0) == '^')) { // '^C'
            if (FLAG_SAVE_DROP)
              Tool.append(FILE_DROP, DATA + "\r\n");
            continue;
          }
        // Hexa
        } else {
          if (FLAG_SAVE_DROP) {
            Tool.append(FILE_DROP, DATA + "\r\n");
            continue;
          }
        }
      }
      
      // Drop terminal control strings (contains 0x1B ESC char)
      if (!contains(DATA, "&S")) {
        if (CONTENT.get(0) instanceof Integer && ((Integer) CONTENT.get(0) == 0x1B)) {
          if (FLAG_SAVE_DROP)
            Tool.append(FILE_DROP, DATA + "\r\n");
          continue;
        } else if (CONTENT.size() > 1 && CONTENT.get(1) instanceof Integer && ((Integer) CONTENT.get(1) == 0x1B)) {
          if (FLAG_SAVE_DROP)
            Tool.append(FILE_DROP, DATA + "\r\n");
          continue;
        }
      }
      
      TMP = developerView(HEADER, DATA, CONTENT);
      
      // 2011-02-25|14:20:53.217697|CLI|23|
      // 20110225.142053.21
      DATE = dim[0] + "." + dim[1].substring(0, dim[1].lastIndexOf(".") + 3);
      DATE = Tool.replace(DATE, "-", "");
      DATE = Tool.replace(DATE, ":", "");

      processPacket(DATE, DATA, CONTENT);
    }
    
    Tool.closeFileReader(br);
  }
  
 /* 
  * Fill up CONTENT<Object> list from my data line
  * 
  * '&START&'·FF·FF·FE·FD·FC·FB·'&END&'
  */
  private List<Object> parseContent(String data) throws IOException {

    String part;
    String[] dim = data.split("[" + DATA_SEP + "]", -1);

    CONTENT.clear();

    for (int i = 0; i < dim.length; i++) {
      part = dim[i];

      if (part.length() > 1) {
        // String object
        if (part.charAt(0) == '\'' && part.charAt(part.length() - 1) == '\'') {
          // Cut off the marker 'chars' and handle escaped ' chars
          part = part.substring(1, part.length() - 1);
          part = Tool.replace(part, "\\'", "'");
          CONTENT.add((String) part);

        // Hexa object
        } else {
          CONTENT.add(Integer.parseInt(part, 16));
        }
        // Globus mark
      } else {
        if (part.equals(DATA_SEP)) {
          CONTENT.add(DELIMITER_7E);
        } else {
          CONTENT.add("Invalid content line!");
          //throw new RuntimeException("FATAL ERROR - Invalid content line! '" + data + "'");
        }
      }
    }
    
    return (CONTENT);
  }

  /* 14:24:08.128011 > '<CALL>'~'CITY.CHK.SOFF.TT.CLOSE'~' ' '&EOT&' 0D
   * 14:24:08.169628   '&START&158'~'0'~'&END&' '&START&158'~'0'~'&END&' '&START&99'~'PH.OFSUSER.1'~'&END&'
   */
  private String developerView(String header, String data, List<Object> list) throws IOException {

    StringBuilder sb = new StringBuilder(64);
  
    for (int i = 0; i < list.size(); i++) {
      Object o = list.get(i);
      
      // Hexa
      if (o instanceof Integer) {
        // Drop first 0A in lines like -> 0A '&SOT&167~' '&EOT&' 0D 
        if (i == 0  && (Integer) o == 0x0A)
          continue;
        //
        if (((Integer) o == 0xFE || (Integer) o == 0x7E) && (contains(data, "&START&") || contains(data, "&EOT&")))
          sb.append(GLOBUS_SEP + " ");
        else
          sb.append(String.format("%02X ", (Integer) o));
        
      // String //////////////////////////////////
      } else {
        // If signo block
        if (o.equals("&START&99")) {
          o = PROPS.getString((String) o);
          // Shorten the signo block
          try {
            
            if (list.get(i + 6) instanceof String)
              TMP = (String) list.get(i + 6);
            else if (list.get(i + 5) instanceof String)
              TMP = (String) list.get(i + 5);
            else if (list.get(i + 4) instanceof String)
              TMP = (String) list.get(i + 4);

            sb.append("'" + o + "'" + GLOBUS_SEP + "'" + (SIGNO = TMP) + "'" + GLOBUS_SEP + "'&END&'");
            
          } catch (Exception e) {
            message("WARN - Broken closing SIGNO block! ");
          }
          break;
        }

        // Check in the dictionary
        if ((TMP = (String) o).startsWith("&SOT&") || (TMP = (String) o).startsWith("&START&")) {
          if (contains(TMP, GLOBUS_SEP))
            TMP = TMP.substring(0, TMP.indexOf(GLOBUS_SEP));
          
          try {
            o = PROPS.getString(TMP);
            
          } catch (MissingResourceException e) {
            if (FLAG_SHOW_UNKNOWN)
              message("WARN - UNKNOWN GLOBUS KEY '" + TMP + "'");
          }
        }
        //
          
        sb.append("'" + o + "' ");
      }
    }

    TMP = sb.toString();
    
    TMP = Tool.replace(TMP, (" " + GLOBUS_SEP), GLOBUS_SEP);
    TMP = Tool.replace(TMP, (GLOBUS_SEP + " "), GLOBUS_SEP);

    // CooL tricks :-)
    if (FLAG_SHOW_NEWLINE && data.indexOf("&START&31") == -1) {  // TODOS
      if (TMP.length() > 90 && data.startsWith("'CITY") == false) {
        TMP = Tool.replace(TMP, "0D 0A ", "0D 0A \r\n");
      }
    }

    if (FLAG_SHOW_NEWLINE && contains(data, "&START&47")) {
      TMP = Tool.replace(TMP, "7D", "7D\r\n");
    }

    if (FLAG_SHOW_TAB && contains(data, "&START&7")) {
      TMP = Tool.replace(TMP, "FF FF", "FF FF\r\n");
      TMP = Tool.replace(TMP, "7F", "7F\r\n");
    }
    //
/*
    if (contains(data, "&START&83")) {
      TMP = Tool.replace(TMP, "FD ", "FD \r\n");
    }
*/
    if (FLAG_SAVE_DEV_VIEW)
      Tool.append(FILE_DEVEL, header + TMP + "\r\n", false);
    
    return (TMP);
  }

  private void autoMessage(String delimiter) throws RemoteException {

    isAUTODELIMITER = true;
    
    message("ERROR - WE DON'T HAVE THE ENVIROMENT NAME YET! (LOGIN FIRST)");
    message("AUTO DELIMITER DETECTION " + delimiter);
    message(STR_LINE);
  }

/*
  '&START&7'·FE·'26647'·FE·'REF.NO'·FD·'REF.NO............'·FD·FE·                                                                                   
  '1'·FE·FE·FE·'A'·FE·FE·FE·'4'·FE·'4'·FE·'2'·FE·FE·FE·FE·'TRANSACTION.TYPE'·FE·'40'·FE·FE·FE·'TRANSACTION.TYPE'·FE·'FT.TXN.TYPE.CONDITION'·FE·FE·FE·FE ... ·FE·FF·FF·
  '2'·FE·FE·FE·'.ALLACCVAL'·FE·FE·FE·'16'·FE·'16'·FE·FE·FE·FE·FE·'DEBIT.ACCT.NO'·FE·'40'·FE·FE·FE·'DEBIT.ACCT.NO'·FE·'ACCOUNT'·FE·FE·FE·FE·FE·'FUNDS.TR ... ·FE·FF·FF·
  '114' FE FE FE 'AMT' FE FE FE '15' FE '15' FE FE 'N' FE FE FE 'TOT.REC.CHG.LCL' FE '40' FE FE FE 'TOT.R' (bad check sum!!!)
  // Multi field  
  '163' FE '161' FE '163' FE 'A' FE  FE  FE '35' FE '35' FE  FE  FE 'N' FE  FE 'ASSN.ADD' FE '40' FE  FE  FE 'ASSN.ADD' FE ...

  '1' TRANSACTION.TYPE (A:4)
  '2' DEBIT.ACCT.NO (ALLACCVAL:16)
  '5' DEBIT.CURRENCY (CCY:3)
*/
  private void getFieldNames(List<Object> content) throws RemoteException {

    String key, name, desc, type;
    String number1, number2, number3;
    
    List<Object> list = null;

    // Try to figure out the correct delimiter chars
    if (ENV.equals("")) {
      if (content.contains(0x7F)) {
        DELIMITER_7E = 0x7E;
        DELIMITER_7F = 0x7F;
        
        if (isAUTODELIMITER == false) {
          autoMessage("(0x7F)");
        }
        
      } else if (content.contains(0xFF)) {
        DELIMITER_7E = 0xFE;
        DELIMITER_7F = 0xFF;
        
        if (isAUTODELIMITER == false) {
          autoMessage("(0xFF)");
        }
        
      } else {
        message("ERROR - CAN'T FIND DELIMITER CHAR! " + content);
      }
    }
    
    try {
      
      for (int i = 0;; i++) {
        if ((list = Robot.getBlock(content, DELIMITER_7F, i)) == null)
          break;

        if (list.size() == 0)
          continue;

        // '173'~~~'RELTIME'~~~'15'~'15'~~'N'~'N'~~'AUDIT.DATE.TIME'~'40'~~~'AUDIT.DATE.TIME'~~~~~~~~~~~~~~~~~~~~~7F
        // ~~~~'1'~'4'~~~~~~'117'~'_______________________________________Debit Information_____________________________________________________________'~~~~~~~~~~~~~~~~~~~7F
        if (Robot.getParam(list, DELIMITER_7E, 0) == null)
          break;
          
        if (list.get(0).equals("&END&"))
          break;
        
        // Cut &START&7 header
        if (i == 0) {
          list = Robot.cutList(list, "1");
        }
        
        // .ALLACCVAL
        type = (String) Robot.getParam(list, DELIMITER_7E, 3);
        if (type != null) {
          if (type.startsWith("."))
            type = type.substring(1);
          type = type + ":";
        } else {
          type = "";
        }
        
        name = (String) Robot.getParam(list, DELIMITER_7E, 16);
        desc = (String) Robot.getParam(list, DELIMITER_7E, 12);
        
        if (name.startsWith("XX")) {
          name = name.substring(3);         
        }
        
        number1 = (String) Robot.getParam(list, DELIMITER_7E, 0);
        number2 = (String) Robot.getParam(list, DELIMITER_7E, 2);
        number3 = (String) Robot.getParam(list, DELIMITER_7E, 4);

        KEY = VERSION + "|" + number1 + "|" + name;
        
        // 'TRANSACTION.TYPE' (A:4)
        TMP = "'" + name + "' (" + type + Robot.getParam(list, DELIMITER_7E, 7) + ")";
        
        // For lookup hashmap
        key = VERSION_LAST + "_" + number1;
        if (FIELDS.get(key) == null) {
          if (TMP.indexOf("null") == -1)
            FIELDS.put(key, TMP);
        }
        //
        
        //Tool.out(" . " + KEY);
      }
      
    } catch (Exception e) {
      //message("WARN - Broken field info data packet! ");
    }
  }
  
  private String TIMESTAMP = "";
   
  private void checkTimestamp(String date) throws RemoteException {
    
    // Duplicated timestamp check
    if (TIMESTAMP.equals(shortTimestamp(date))) {
      message("WARN - SAME TRANSACTION TIMESTAMP! '" + TIMESTAMP + "'");

    } else {
      TIMESTAMP = new String(shortTimestamp(date));
    }
  }

  // Example 20110726.174052
  private String shortTimestamp(String date) {
    
    return (date.substring(0, date.length() - 3));
  }
  
/*
  20110719.171610.12-LOGIN-BURO40.tcr
  LOGIN|BURO.40|123456|

  20110719.172325.45-LOGOUT-BURO40.tcr
  LOGOUT|BURO.40|
*/
  private void saveLoginFile(String date, String user, String password) throws IOException {
    
    checkTimestamp(date);
    FILE_OUTPUT = date + "-LOGIN-" + user;
    
    Tool.save(PATH + SEP + FILE_OUTPUT + EXT_TCR, "LOGIN|" + user + "|" + password + "|\r\n");
    message("* SAVE '" + FILE_OUTPUT + EXT_TCR + "'");
  }

  private void saveLogoutFile(String date, String user) throws IOException {
    
    checkTimestamp(date);
    FILE_OUTPUT = date + "-LOGOUT-" + user;
    
    Tool.save(PATH + SEP + FILE_OUTPUT + EXT_TCR, "LOGOUT|" + user + "|\r\n");
    message("* SAVE '" + FILE_OUTPUT + EXT_TCR + "'");
  }

  private void saveTCRFile(StringBuilder sb) throws IOException {
    
    if (cityFilter(true))
      return;

    TMP = sb.toString();

    // Inject TELLERID at save time
    if (contains(TMP, "@TELLER@")) {
      if (TELLERS.get(USER) != null)
        TMP = Tool.replace(TMP, "@TELLER@", TELLERS.get(USER));
      else
        TMP = Tool.replace(TMP, "@TELLER@", "");
    }

    // Inject MODE at save time
    if (contains(TMP, "@MODE@")) {
      TMP = Tool.replace(TMP, "@MODE@", MODE);
    }

    if (FILE_OUTPUT.equals(FILE_BACKUP) == false) {
      SUMMA_TRANSACTION++;
      FILE_BACKUP = FILE_OUTPUT;
      
      if (TMP.length() < 32) {
        message("ERROR - * SAVE 'EMPTY HEADER!'");
        return;
      } else {
        checkTimestamp(FILE_OUTPUT.substring(0, FILE_OUTPUT.indexOf("-")));
        message("* SAVE '" + FILE_OUTPUT + EXT_TCR + "'");
      }

    } else {
      message("* APPEND '" + FILE_OUTPUT + EXT_TCR + "'");
    }

    // Finally save it
    Tool.save(PATH + SEP + FILE_OUTPUT + EXT_TCR, TMP);
  }

/*
   '&SOT&133'·FE·'FT,'·'&EOT&'·0D
   '&START&133'·FE·'15'·FE·'FUNDS.TRANSFER,&END&'

   '&SOT&12'·FE·'&EOT&'·0D
   '&START&6' ... '&START&11'·FE·'42'·FE·'FT10284001004715'·FE·'FT/10284/001004715     '·FE·FE·'&END&'
*/
  
  private static final int CMD_NOP = 0;
  private static final int CMD_BANK_DATE = 1;
  private static final int CMD_LOGIN = 2;
  private static final int CMD_OPEN_VERSION = 3;
  private static final int CMD_MAKE_NEW = 4;
  private static final int CMD_SET_FIELD = 5;
  private static final int CMD_SET_TRID = 6;
  private static final int CMD_COMMIT = 7;
  private static final int CMD_CLOSE_VERSION = 8;
  private static final int CMD_MENU = 9;
  private static final int CMD_TELLER_ID = 10;
  private static final int CMD_DEL_MULTIVALUE = 11;
  private static final int CMD_COMMIT_ERROR = 12;
  private static final int CMD_ERROR = 13;
  private static final int CMD_ENQUIRY = 14;
  private static final int CMD_CLOSE_WINDOW = 15;
  
  private int LAST = CMD_NOP;
  private int LAST_BACKUP = CMD_NOP;
  
  private StringBuilder BUILDER = new StringBuilder();

  private void initTCRHeader(String date, String prefix, String trid) throws RemoteException {
    
    HEADER = "";
    TYPE = (LAST == CMD_MAKE_NEW ? "NEW" : "UPDATE");
    
    if (inSECONDLEG == false) {
      if (trid.equals(TRID) == false) {
        TRID = trid;
        
        if ((prefix.equals("SET TRID") || prefix.equals("TRID")) && MODE.equals("?")) {
          MODE = "I";
          message(prefix + " '" + TRID + "' '" + TYPE + "' 'I'");
        } else {
          message(prefix + " '" + TRID + "' '" + TYPE + "'" + (TYPE.equals("NEW") ? " 'I'" : ""));
        }

        // In Copy mode add the original TRID too
        TMP = (TRID_COPY.equals("") ? "" : TRID_COPY + "/") + TRID; 
        
        HEADER = VERSION + "/@MODE@/" + TYPE + HEADER_SEP + USER + "/" + PASSWORD + "/@TELLER@" + HEADER_SEP + TMP + HEADER_SEP;
      }
      
      FILE_OUTPUT = date + "-" + VERSION + "-" + TRID;
    }

    // Save header
    if (inSECONDLEG) {
      if (trid.equals(TRID) == false || inSPECIALSECONDLEG) {
        TRID = trid;
        message(prefix + " '" + TRID + "' '" + TYPE + "'") ;
        HEADER = "LEG" + HEADER_SEP + TRID + HEADER_SEP + VERSION_SECOND_LEG + HEADER_SEP;
      }
    }

    if (HEADER.length() > 0) {
      // If we have something in the BUILDER before adding the header
      if (inSECONDLEG == false && BUILDER.length() != 0) {
        resetBuilder();
        BUILDER.append(HEADER + "\r\n");
        message("WARN - SPECIAL CHANGE THE HEADER!");
        
      } else {
        BUILDER.append(HEADER + "\r\n");
      }
    }
  }

  private void resetBuilder() {
    
    BUILDER = new StringBuilder(64);
  }

  private void resetOpenState() {

    LAST = CMD_NOP;
    inCOMMIT = COMMIT_NOP;

    inSECONDLEG = false;
    liveNotChanged = false;
    
    MODE = TRID = TRID_COPY = VERSION_SECOND_LEG = "";
  }

  private void processPacket(String date, String data, List<Object> content) throws IOException {

    int last, index;
    String tmp, cmd;
    boolean canSave = false;
    
//  message(">>> " + LAST + " " + Tool.printList(content));
    
    List<Object> part = content;
    
    for(int i = 0; i < content.size(); i++) {
      Object o = content.get(i);

      // Starts with "0A &SOT&"
      if (i == 0 && o instanceof Integer && o.equals(0x0A)) {
        if (contains(data, "&S")) {
          continue;
        }
      }

      // String value
      if (o instanceof String) {
        cmd = (String) o;

        if (cmd.startsWith("&S") == false)
          continue;

        if (cmd.equals("&START&99"))
          continue;

        part = Robot.cutList(content, i, true);
        
        ////////////////////////////////////////////////////////////
        
        // ACK TAB
        if (cmd.equals("&START&7")) {
          getFieldNames(part);
          continue;
        }

        // ACK ENV
        // '&START&135'·FE·'5'·FE·'VVNEW'·'&END&'
        if (cmd.equals("&START&135")) {

          TMP = (String) part.get(4);
          if (ENV == null || ENV.equals(TMP) == false) {
            message("ENVIROMENT '" + (ENV = TMP) + "'");
            FIELDS.clear();
          }
        }

        // ACK OPEN
        // '&START&133'·7E·'30'·7E·'FUNDS.TRANSFER,CITY.LIMIT.CHG I'·'&END&'
        if (cmd.equals("&START&133") && LAST == CMD_OPEN_VERSION) {
          USER = SIGNO;
          VERSION_FULL = "" + part.get(4);
          
          if ((index = VERSION_FULL.indexOf(' ')) != -1)
            VERSION_FULL = VERSION_FULL.substring(0, index);

          if (inSECONDLEG && inCOMMIT == COMMIT_SECOND_LEG) {
            TMP = "OPEN SECOND LEG";
            LAST = CMD_SET_FIELD;
            
          } else {
            TMP = "OPEN VERSION";
            resetBuilder();
            FILTER_USER_COPY = SIGNO;
            FILTER_VERSION_COPY = new String(VERSION);

            if (MODE.equals("L"))
              TMP = "LIST VERSION";
                        
            TRID = TRID_COPY = "";
          }

          // Make open header
          if (OTRID.equals("") == false)
            LOG_HEADER = "(" + SUMMA_OPEN + ") " + TMP + " '" + VERSION + " " + MODE + " " + OTRID + "' (" + USER + ")";
          else
            LOG_HEADER = "(" + SUMMA_OPEN + ") " + TMP + " '" + VERSION + " " + MODE + "' (" + USER + ")";

          if (inSECONDLEG)
            _message_(LOG_HEADER);
          else
            _message(LOG_HEADER);

          // If the TRID was set directly in the open version line
          if (OTRID.equals("") == false && OTRID.equals("L") == false) {
            if (OTRID.equals("F3")) {
              message("WARN - SPECIAL TRID 'F3'");
              LAST = CMD_MAKE_NEW;
              TRID = OTRID;
            }
            
            initTCRHeader(date, "SET TRID DIRECTLY", OTRID);
          }
          
          continue;
        }

        // COMMIT
        if (cmd.equals("&SOT&20")) {
          LAST = CMD_COMMIT;
          inCOMMIT = COMMIT_BEGIN;
          message("COMMIT 'BEGIN' ");
          continue;
        }

        // HOLD
        if (cmd.equals("&SOT&21")) {
          message("* HOLD RECORD *");
          BUILDER.append("(::) 'COMMAND' = '{HOLD}'\r\n");
          canSave = true;
          continue;
        }

        // ACK LIST
        // '&START&5'·FE·'107'·FE·'ACCOUNT,CITY.PRIV.STD'·FE·'ACCOUNT'·FE· ...
        if (cmd.equals("&START&5")) {
          TMP = (String) part.get(4);
          if (inCOMMIT == COMMIT_BEGIN || inCOMMIT == COMMIT_TXN_COMPLETE || inCOMMIT > COMMIT_TXN_FAILED) {
            inSECONDLEG = true;
            VERSION_SECOND_LEG = TMP;
            inCOMMIT = COMMIT_SECOND_LEG;

            if (VERSION.equals("LD,CITY.NEW.LOAN.PVT") && TMP.equals("LD.SCHEDULE.DEFINE,STD")) {
              message("WARN - SPECIAL SECOND LEG WITHOUT TRID");
              initTCRHeader(date, "TRID", TRID);
            }
          }
        }

        // ASK DATA
        // '&SOT&148'·FE·'F.VERSION'·FE·'ACCOUNT,CITY.PRIV.STD'·FE·'D.SLIP.TRIGGER'·FD·'D.SLIP.FORMAT'·'&EOT&'·0D 
        if (cmd.equals("&SOT&148")) {
          if (part.get(2).equals("F.VERSION")) {
            if ((TMP = (String) part.get(4)) != null) {
              // Enter second leg
              if (TMP.startsWith(VERSION_SECOND_LEG) && inCOMMIT == COMMIT_SECOND_LEG) {
                inSECONDLEG = false;
                LAST = CMD_OPEN_VERSION;
                VERSION_LAST = new String(TMP);
                _message_("SECOND LEG '" + TMP + "'");
              }

//            message("*** SPECIAL CHANGE VERSION *** '" + TMP + "'");
            }
          }
          
          continue;
        }
        
        // ACK TRID
        // '&START&11'·FE·'42'·FE·'FT10284001004715'·FE·'FT/10284/001004715 '·FE·FE·'&END&'·
        // '&START&11'·7E·'36'·7E·'FX1105300026'·7E·'FX-11053-00026'·7E·'1ST LEG'·7E·'&END&'
        // '&START&11'·7E·'55'·7E·'FX1105300027'·7E·'FX-11053-00027'·7E·'   2ND LEG OF FX1105300026'·7E·'&END&'
        if (cmd.equals("&START&11")) {
          TMP = ((String) part.get(4));

          if (part.size() > 8 && part.get(8) instanceof String) {
            if (ACK == null || ACK.equals(part.get(8)) == false)
              message("ACK TRID '" + (ACK = Tool.leftTrim((String) part.get(8))) + "'");
          }

          // In this case we dont need the TRID value
          if (LAST == CMD_SET_TRID) {
            // *** TRICK ALARM *** for CITY.STANDING.ORDER '5011975911113282.3'
            if (VERSION.startsWith("CITY.STANDING.ORDER") && !TMP.equals(TRID) && (index = TMP.lastIndexOf('.')) != -1) {
              tmp = TMP.substring(0, index);
              tmp = Tool.replace(BUILDER.toString(), tmp, "TCRLOOKUP:" + tmp + "_" + TMP.substring(index));
              BUILDER = new StringBuilder(tmp);
            }
            // ***

            if (!MODE.equals("S")) {
              TRID = TMP;
            }
            
            message("TRID '" + TMP + "'");
            continue;
          }
          
          // Same TRID arrived from the server
          if (TMP.equals(TRID)) {
  
            if(inCOMMIT == COMMIT_SECOND_LEG && inSECONDLEG == true) {
//            if (VERSION_HEAD.startsWith("ACCOUNT") || VERSION_HEAD.startsWith("AC")) {
              inSPECIALSECONDLEG = true;
              message("WARN - SPECIAL SECOND LEG WITH THE SAME TRID!");
              
            } else {
              continue;
            }
            
          } else {
            // *** TRICK ALARM ***
            // CITY.BATCH.HEADER,CITY.PROMPT.COLLECTION/I/NEW|BURO.05/123456/|BH1105300008|
            // CITY.BATCH.HEADER,CITY.PROMPT.COLLECTION/I/UPDATE|BURO.05/123456/|BH1105300008000001|
            if (inCOMMIT != COMMIT_NOP) {
              if (VERSION_HEAD.startsWith("CITY.BATCH") && TMP.length() < 15) {
                message("WARN - SPECIAL DROP THE SHORT TRID!");
                continue;
              }
              
//            if (LAST != CMD_MAKE_NEW)
//              inSECONDLEG = true;

            } else {
              if (VERSION_HEAD.startsWith("CITY.BATCH") && TMP.length() > 15) {
                message("WARN - SPECIAL DROP THE LONG TRID!");
                TRID = TMP;
                continue;
              }
              
//            inSECONDLEG = false;
            }
            // ***
          }

//        if (TRID.equals("")) {
//          inSECONDLEG = false;
//        }

          if (LAST == CMD_MAKE_NEW && !TRID.equals("")) {             
            SUMMA_OPEN++;
            resetBuilder();
            LOG_HEADER = "(" + SUMMA_OPEN + ") SAME VERSION '" + VERSION + " " + MODE + "' (" + USER + ")";
            _message(LOG_HEADER);
          }           
          
          initTCRHeader(date, "TRID", TMP);
          
          if (LAST == CMD_MAKE_NEW) 
            LAST = CMD_SET_FIELD;
          
          continue;
        }

        // SET TRID
        // '&SOT&29'·7E·'FT10293001000002'·'&EOT&'·0D
        if (cmd.equals("&SOT&29")) {
          TMP = (String) part.get(2);

          if (BUILDER.length() > 0) {
            if (TRID.equals(TMP)) {
              LAST = CMD_SET_TRID;
              
              if (liveNotChanged) {
                SUMMA_OPEN++;
                resetBuilder();
                inSECONDLEG = liveNotChanged = false;
                inCOMMIT = COMMIT_NOP;

                // Use the second leg version
                VERSION = VERSION_LAST;
                message("WARN - SPECIAL LIVE NOT CHANGED");

                LOG_HEADER = "(" + SUMMA_OPEN + ") KEEP VERSION '" + VERSION + " " + MODE + "' (" + USER + ")";
                _message(LOG_HEADER);
                
              } else {
                message("WARN - SET TRID '" + TMP + "' AGAIN");
                continue;
              }
              
            } else {
              if (Tool.isNull(TRID) == false && TMP.endsWith(TRID)) {
                LAST = CMD_SET_TRID;
                resetBuilder();
                message("WARN - SET TRID '" + TMP + "' CHANGE");
                BUILDER.append(Tool.replace(BUILDER.toString(), TRID, TMP));
                TRID = TMP;
                continue;
              }
            }
          }

          if (!ENV.equals("") && LAST == CMD_NOP) {
            SUMMA_OPEN++;
            resetBuilder();
            inSECONDLEG = false;
            inCOMMIT = COMMIT_NOP;
            
            LOG_HEADER = "(" + SUMMA_OPEN + ") KEEP VERSION '" + VERSION + " " + MODE + "' (" + USER + ")";
            _message(LOG_HEADER);
            
            if (MODE.equals("C")) {
              TRID_COPY = TRID;
            }
          }

          TRID = "";
          LAST = CMD_SET_TRID;

          initTCRHeader(date, "SET TRID", TMP);
          continue;
        }

        // MAKE MULTIVALUE
        // '&SOT&17' FE 'M' FE '39.8.0' FE '&EOT&'
        // '&SOT&17' FE 'M' FE '17.2.0' FE '18.2.0' FE '19.2.0' FE '20.2.0' FE '21.2.0' FE '22.2.0' FE '23.2.0' FE '24.2.0' FE '&EOT&' 
        // '&SOT&17' FE 'M' FE '17.5.0' FE '18.5.0' FE '19.5.0' FE '20.5.0' FE '21.5.0' FE '22.5.0' FE '23.5.0' FE '24.5.0' FE '&EOT&'
        // '&SOT&17' 7E 'M' 7E '4.2.0' 7E '5.2.0' 7E '6.2.0' 7E '7.2.0' 7E '8.2.1' 7E '9.2.1' 7E '10.2.0' 7E '11.2.0' 7E '12.2.1' 7E '13.2.1' 7E '14.2.1' 7E '15.2.1' 7E '16.2.0' 7E '17.2.0' 7E '18.2.1' 7E '19.2.0' 7E '&EOT&' 
        if (cmd.equals("&SOT&17")) {
          
          TMP = (String) part.get(4);
          FIELD = lookupFIELD(TMP.substring(0, TMP.indexOf(".")));
          TMP = Tool.replace(TMP, ".", ":");

          // Keep only the field's name 'TRANSACTION.TYPE' (A:4)
          if (contains(FIELD, "'"))
            FIELD = FIELD.substring(0, FIELD.lastIndexOf("'") + 1);

          VALUE = "";
          for (int a = 0; a < part.size() - 5; a = a + 2) {
            VALUE = VALUE + "-" + part.get(a + 4);
          }

          VALUE = "'{MAKE-MULTI" + VALUE + "}'";

          message("MAKE MULTIVALUE (" + TMP + ") " + FIELD + " - " + VALUE);

          // Build TCR file
          BUILDER.append("(" + TMP + ") " + FIELD + " = " + VALUE + "\r\n");
          //
          
          continue;
        }

        // SET TEXTBOX
        // '&SOT&34' FE 'BORKA' FE '10' FE ' 1' FE ' 0' FE '&EOT&'
        if (cmd.equals("&SOT&34")) {

          VALUE = (String) part.get(2);
          FIELD = lookupFIELD((String) part.get(4));
          TMP = part.get(4) + ":" + part.get(6) + ":" + part.get(8);
          TMP = Tool.replace(TMP, " ", "");

          message("SET TEXTBOX (" + TMP + ") " + FIELD + " - '{SET-TEXTBOX-" + VALUE + "}'");

          if (contains(FIELD, "'"))
            FIELD = FIELD.substring(0, FIELD.lastIndexOf("'") + 1);

          // Build TCR file
          BUILDER.append("(" + TMP + ") " + FIELD + " = '{SET-TEXTBOX-" + VALUE + "}'\r\n");
          //
          continue;
        }

        // SET FIELD
        // '&SOT&14' FE 'HUF' FE '5' FE ' 0' FE ' 0' FE '&EOT&' 0D
        if (cmd.equals("&SOT&14")) {
          LAST = CMD_SET_FIELD;
          
          // No value
          if (part.get(2) instanceof Integer) {
            VALUE = "";
            index = 3;
          } else {
            VALUE = (String) part.get(2);
            index = 4;
          }

          TMP = (String) part.get(index);
          FIELD = lookupFIELD(TMP);

          TMP = TMP + ":" + (String) part.get(index + 2) + ":"  + (String) part.get(index + 4);

          TMP = Tool.replace(TMP, " 0", "");
          TMP = Tool.replace(TMP, " ", "");

          // *** TRICK ALARM ***
          if (contains(FIELD, "(ALLACCVAL:"))
            VALUE = "TCRLOOKUP:" + VALUE;

          for (int a = 0; a < TCRLOOKUP.length; a++) {
            if (FIELD.startsWith("'" + TCRLOOKUP[a])) {
              VALUE = "TCRLOOKUP:" + VALUE;
              break;
            }
          }
          // ***
          
          message("SET FIELD (" + TMP + ") " + FIELD + " - '" + VALUE + "'");

          // Keep only the field's name 'TRANSACTION.TYPE' (A:4)
          if (contains(FIELD, "'"))
            FIELD = FIELD.substring(0, FIELD.lastIndexOf("'") + 1);

          // Build TCR file
          BUILDER.append("(" + TMP + ") " + FIELD + " = '" + VALUE + "'\r\n");
          continue;
        }

        // OPEN VERSION
        if (cmd.equals("&SOT&133")) {

          if (LAST == CMD_MAKE_NEW) {
            message("ERROR - SIMULTANEOUS VERSION OPENS! (use +FLAG_USE_PORT_NUMBER)");
          }

          // *** TRICK ALARM ***
          if (inCOMMIT == COMMIT_BEGIN || inCOMMIT > COMMIT_TXN_FAILED) {
            if (VERSION.startsWith("FOREX") || VERSION.startsWith("FX")) {
              message("WARN - COMMIT DOESN'T CLOSED!");
//            inSECONDLEG = true;
              
            } else {              
              if (LAST == CMD_COMMIT_ERROR) {
                resetOpenState();
                message("ERROR 'COMMIT FAILED' *** TXN DROP ***");
                
              } else {                
                if (VERSION_LAST.equals(part.get(2))) {
                  
                  HEADER = "LEG" + HEADER_SEP + TRID + HEADER_SEP + "" + HEADER_SEP;
                  BUILDER.append(HEADER + "\r\n");
                
//                inSECONDLEG = true;
                  message("WARN - COMMIT DOESN'T CLOSED (SECOND LEG WITH THE SAME TRID)!");
                  
                } else {
                  resetOpenState();
                  message("ERROR 'COMMIT' 'DIFFERENT VERSION NAME' *** TXN DROP ***");                
                }
              }
            }
          }
          // ***

          LAST = CMD_OPEN_VERSION;
          SUMMA_OPEN++;

          TMP = (String) part.get(2);
          
          // *** TRICK ALARM ***
          if (inSECONDLEG && VERSION_LAST.startsWith("CITY.BATCH") && !TMP.startsWith("CITY.BATCH")) {
            message("*** SPECIAL THIS IS NOT A SECOND LEG! ***");
            inSECONDLEG = false;
          }
          // ***
          
          VERSION = VERSION_LAST = TMP;
          OTRID = "";
          
          if (inSECONDLEG == false)
            VERSION_HEAD = new String(TMP);           
            
          // Get open mode char
          if ((index = VERSION.indexOf(" ")) != -1) {
            String mode = "" + VERSION.charAt(index + 1);
            
            if (Tool.contains(modeList, mode)) {            
              MODE = mode;
              
            } else {
              // AC, 5070698611103283
              TMP = VERSION.substring(index + 1);
              
              if (!TMP.equals(",")) {
                OTRID = TMP;
                TRID = TRID_COPY = "";
//              inSECONDLEG = false;
                message("WARN - SPECIAL SET TRID WITHOUT MODE '" + VERSION + "'");
              }
            }
            
            // If TRID is in the open command like 'FT S FT11073012000076'
            if ((last = VERSION.lastIndexOf(" ")) != index) {
              OTRID = VERSION.substring(last + 1);
              TRID = TRID_COPY = "";
//            inSECONDLEG = false;
            }
            
            VERSION = VERSION_LAST = VERSION.substring(0, index);
            
          } else {
            MODE = "?";
          }

          if (VERSION.endsWith(",")) {
            MODE = "I";
          }
          
          VALUE = ""; 
          inCOMMIT = COMMIT_NOP;
          LAST_BACKUP = CMD_NOP;
          
          liveNotChanged = false;         
          continue;
        }

        // OPEN RESULT
        // '&SOT&49' FE '%CUSTOMER_HU0010001_T-U.059392' FE '1ü6' FE '&EOT&'
        if (cmd.equals("&SOT&49")) {
          message("OPEN RESULT '" + (String) part.get(2) + "' '" + getSotParam(part, 4) + "'");
          continue;
        }
  
        // OPEN ENQ
        // '&SOT&50'·FE·'%LIMIT,CITY.BANK.INPUT.GLOBAL'·'&EOT&'·0D
        if (cmd.equals("&SOT&50")) {
          LAST = CMD_ENQUIRY;
          message("OPEN ENQUIRY '" + (String) part.get(2) + "'");
          continue;
        }

        // RUN ENQ
        // '&SOT&44'·FE·'%LIMIT,CITY.BANK.INPUT.GLOBAL'·FE·FD·FD·FD·FD·'&EOT&'·0D
        // '&SOT&44'·FE·'CITY.CUSTOMER.MAIN'·FE·'@IDüGLOBUS AZONOSÍTÓ'·FD·'EQ'·FD·'10266021'·FD·FD·'&EOT&'·0D
        if (cmd.equals("&SOT&44")) {
          if ((TMP = getSotParam(part, 4)).length() > 0) {
            TMP = getSotParam(part, 4) + "·" + getSotParam(part, 6) + "·" + getSotParam(part, 8);
            
            if (part.size() > 12)
              message("WARN - WE HAVE MORE ENQ PARAMETERS HERE!");
          }

          LAST = CMD_ENQUIRY;
          message("RUN ENQUIRY '" + (String) part.get(2) + "' '" + TMP + "'");
          continue;
        }

        // LIST ENQ
        // '&SOT&79'~'ACCOUNT.DEBIT.INT'~~~'ID' '&EOT&'
        if (cmd.equals("&SOT&79")) {
          LAST = CMD_ENQUIRY;
          message("LIST ENQUIRY '" + part.get(2) + "' '" + getSotParam(part, 5) + "'");
          continue;
        }

        // COMBO ENQ
        // '&SOT&80'~'CITY.TT.MISC'~'FLD.NAME EQ "ACCOUNT.2"'~'CITY.TT.MISC' '&EOT&'
        if (cmd.equals("&SOT&80")) {
          LAST = CMD_ENQUIRY;
          message("COMBO ENQUIRY '" + part.get(2) + "'");
          continue;
        }

        // SOME ENQ
        // '&SOT&54'~'%LIMIT-DEFAULT_HU0010001_T-U.061735T'~'@ID' FD 'EQ' FD '10356390.0020000.01' '&EOT&'

        // ERROR
        // '&START&2'~'29'~'LEC0094 New input not allowed'~'&END&'
        if (cmd.equals("&START&2")) {
          if ((TMP = (String) part.get(4)) != null) {
            if (VALUE.equals("") || TMP.startsWith(VALUE) == false) {
              //
              if (inCOMMIT != COMMIT_NOP) {
                if (TMP.equals("INPUT IS NOT INPUTTERS VALUE") || TMP.equals("NEM MEGFELELÕ ÉRTÉK"))
                  message("WARN 'COMMIT' '" + TMP + "'");
                else
                  message("ERROR 'COMMIT' '" + TMP + "'");
                
              } else {
                if (TMP.equals("UNAUTH. RECORD MISSING") || TMP.equals("AUTHORIZÁLATLAN TÉTEL HIÁNYZIK")) {
                  message("WARN '" + TMP + "'");
                } else {
                  
                  if (TMP.startsWith("NO RECORD(S)")) {
                    resetOpenState();
                    message("WARN '" + TMP + "' *** TXN DROP ***");
                    
                  } else if (TMP.startsWith("NEM ENGEDÉLYEZETT FUNKCIÓ")) {
                    resetOpenState();
                    message("WARN '" + TMP + "' *** TXN DROP ***");

                  } else {
                    message("ERROR '" + TMP + "'");
                  }
                }
              }

              VALUE = TMP;
            }
          }
          
          continue;
        }

        // ACK SET
        // '&START&9'~'35'~'0.138.40'~~~~'ID IN FILE MISSING'~'177' 7F '&END&'
        // '&START&9'~'67'~'0.93'~'P91'~'P91'~~'LEC0087 No record in CITY.SPECIAL.TREATMENT'~'93' 7F '&END&'
        if (cmd.equals("&START&9")) {         
          if ((TMP = (String) Robot.getParam(part, DELIMITER_7E, 6)) != null)
            if (inCOMMIT != COMMIT_NOP && inCOMMIT != COMMIT_SECOND_LEG) {
              LAST = CMD_COMMIT_ERROR;
              message("ERROR 'COMMIT' '" + TMP + "'");
            } else
              message("ERROR '" + TMP + "'");

          continue;
        }

        // POPUP
        // '&START&30'·7E·'22'·7E·'ENTER TELLER ID'·7E·7E·7E·7E·'Y'·7E·'4'·'&END&'·
        // '&START&30'·7E·'45'·7E·'# Debit Account..........'·7E·'PLEASE REKEY'·7E·7E·7E·'Y'·7E·'16&END&'
        // @see processCommit()
        if (cmd.equals("&START&30") && LAST != CMD_COMMIT && LAST != CMD_LOGIN) {
          TMP = "" + part.get(4);
          message("POPUP '" + TMP + "'");
          
          if (TMP.equals("ENTER TELLER ID")) {
            LAST_BACKUP = LAST;
            LAST = CMD_TELLER_ID;
          }

          if (TMP.equals("VÁLTOZTATÁSOK NINCSENEK MENTVE") || TMP.equals("CHANGES NOT SAVED")) {
            LAST_BACKUP = LAST;
            LAST = CMD_CLOSE_WINDOW;
          }

          continue;
        }

        // CLOSE VERSION
        if (cmd.equals("&SOT&56")) {
          // '<CLOSE.VERSION>'~'KEEPALIVE' '&EOT&' 0D
          // '<CLOSE.VERSION>'~'LD.LOANS.AND.DEPOSITS' '&EOT&' 0D 
          if ((TMP = (String) part.get(2)) != null)
            message("CLOSE VERSION '" + TMP + "'");
          else
            message("CLOSE VERSION");
          
          resetOpenState();         
          LAST = CMD_CLOSE_VERSION;
          
          continue;
        }

        // LOGIN
        if (cmd.equals("&SOT&24")) {
          USER = (String) part.get(2);
          PASSWORD = (String) part.get(4);
          
          resetOpenState();
          LAST = CMD_LOGIN;
          continue;
        }
        
        // BANK DATE
        if (cmd.equals("&SOT&130")) {
          LAST = CMD_BANK_DATE;
          continue;
        }

        // MAKE NEW (F3)
        if (cmd.equals("&SOT&12")) {
          
          if (!ENV.equals("") && LAST == CMD_NOP) {
            SUMMA_OPEN++;
            resetBuilder();
            inSECONDLEG = false;
            inCOMMIT = COMMIT_NOP;

            LOG_HEADER = "(" + SUMMA_OPEN + ") KEEP VERSION '" + VERSION + " " + MODE + "' (" + USER + ")";
            _message(LOG_HEADER);
          }

          MODE = "I";
          LAST = CMD_MAKE_NEW;
          message("CREATE NEW RECORD 'F3'");
          continue;
        }       

        // SET MODE
        // '&SOT&28'·FE·'S'·'&EOT&'·0D
        if (cmd.equals("&SOT&28")) {
          if ((TMP = (String) part.get(2)) != null) {
            if (!MODE.equals(TMP)) {
              MODE = TMP;
              message("SET MODE '" + TMP + "'");
              
              // Copy mode
              if (MODE.equals("C")) {
                TRID_COPY = TRID;
                continue;
              }
              
              // Delete mode
              if (MODE.equals("D") && inCOMMIT != COMMIT_NOP) {
                SUMMA_OPEN++;
                TMP = TRID;
                resetBuilder();
                resetOpenState();

                MODE = "D";
                LOG_HEADER = "(" + SUMMA_OPEN + ") DELETE VERSION '" + VERSION + " " + MODE + "' (" + USER + ")";
                _message(LOG_HEADER);

                initTCRHeader(date, "SET TRID", TMP);
                continue;
              }
              
              if (!MODE.equals("S") && inCOMMIT != COMMIT_NOP) {
                message("WARN - TEST SPECIAL MODE CHANGE");
              }
            }
          }
          
          continue;
        }       

        // ACTION
        // '&SOT&1'·7E·'Y'·'&EOT&'·0D
        // '&SOT&1'·FE·'CONTINUE'·'&EOT&'·0D
        if (cmd.equals("&SOT&1")) {
          
          if ((TMP = (String) part.get(2)) != null) {
            if (TMP.equals("&EOT&") == false)
              message("ACTION '" + TMP + "'");
//          else
//            message("'OKAY'");
          }

          // AFTER CLOSE WINDOW
          if (LAST == CMD_CLOSE_WINDOW) {
            if (TMP.startsWith("Y")) {
              resetOpenState();
              MODE = "I";
              message("WARN - SPECIAL CLOSE WINDOW EVENT");
              continue;
              
            } else {
              LAST = LAST_BACKUP;
            }

          // AFTER ENTER TELLER ID  
          } else if (LAST == CMD_TELLER_ID) {
            if (TMP.equals("CANCEL") || TMP.equals("&EOT&")) {
              LAST = CMD_NOP;
              continue;
            }
            
            if (TELLERS.containsKey(USER) == false) {
              TELLERS.put(USER, TMP);
            }
            
            if (LAST_BACKUP == CMD_MAKE_NEW) {
              LAST = CMD_MAKE_NEW;
            } else {
              LAST = CMD_SET_FIELD;
            }
          }
          
          continue;
        }
        
        // DELETE MULTIVALUE
        // '&SOT&18'·FE·'M'·FE·'37. 2. 0'·FE·'&EOT&'·0D
        // '&SOT&18'·FE·'M'·FE·'50. 21. 0'·FE·'51. 21. 0'·FE·'52. 21. 0'·FE·'&EOT&'·0D 
        if (cmd.equals("&SOT&18")) {
          LAST = CMD_DEL_MULTIVALUE;

          // '37. 2. 0'
          String[] dim = ((String) part.get(4)).split(". ", -1);

          FIELD = lookupFIELD(dim[0]);
          TMP = dim[0] + ":" + dim[1] + ":" + dim[2];

          List<Object> list = Robot.cutList(part, 0, true);
          int cnt = (list.size() - 5) / 2;

          if (contains(FIELD, "'"))
            FIELD = FIELD.substring(0, FIELD.lastIndexOf("'") + 1);

          message("DELETE MULTIVALUE (" + TMP + ") " + FIELD + " - '{DELETE-MULTI-" + cnt + "}'");

          // Build TCR file
          BUILDER.append("(" + TMP + ") " + FIELD + " = '{DELETE-MULTI-" + cnt + "}'\r\n");
          //
          continue;
        }
        
        // MENU
        if (cmd.equals("&SOT&129")) {
          LAST = CMD_MENU;
          continue;
        }
        
        // LOGOUT
        // '&SOT&4'·7E·'SIGN.OFF'·'&EOT&'·0D
        // '&SOT&4'·FE·'SIGN.OFF LOGOUT'·'&EOT&'·0D
        if (cmd.equals("&SOT&4")) {
          if ((TMP = (String) part.get(2)) != null) {
            if (TMP.startsWith("SIGN.OFF")) {
              
              if (gLOGINS.contains(USER)) {
                gLOGINS.remove(USER);
                message(STR_LINE);
                message("* LOGOUT '" + Tool.replace(USER, ".", "") + "' at " + shortTimestamp(date));
                saveLogoutFile(date, USER);
                
              } else {
                message("ERROR - LOGOUT 'UNKNOWN USER NAME' '" + Tool.replace(USER, ".", "") + "'");
              }
              
              USER = "";
              LAST = CMD_NOP;
            }
          }
          continue;
        }

        // Skip these well known commands 
        // SESSION LOAD.MENU GET.MENU GET.ENV CALL GET.TAB GET.DATA and OPEN.DESKTOP
        if (cmd.startsWith("&SOT&99p") || cmd.equals("&SOT&26") || cmd.equals("&SOT&106") || 
            cmd.equals("&SOT&135") || cmd.equals("&SOT&158") || cmd.equals("&SOT&7") || 
            cmd.equals("&SOT&8") || cmd.equals("&SOT&33") || cmd.equals("&SOT&83")) {
          
          continue;
        }

        // SHOW UNKOWN SOT COMMAND ONLY ONCE
        if (cmd.startsWith("&SOT&")) {
          if (!uniqueSotList.contains(cmd)) {
            uniqueSotList.add(cmd);
            message("WARN - UNKNOWN SOT COMMAND - " + Tool.printList(part));
          } else {        

          // THIS IS MY TEST 
//        if (cmd.equals("&SOT&17"))
//            message("WARN - UNKNOWN SOT COMMAND - " + Tool.printList(part));
          }         
        }

        ////////////////////////////////////////////////////

        if (LAST == CMD_DEL_MULTIVALUE) {
          LAST = CMD_SET_FIELD;         
        }

        // AFTER OPEN 
        if (LAST == CMD_OPEN_VERSION) {
          LAST = CMD_SET_FIELD;
          continue;
        }

        // AFTER MENU
        if (LAST == CMD_MENU) {
          USER = SIGNO;
          LAST = CMD_NOP;
          continue;
        }

        // AFTER BANK DATE
        if (LAST == CMD_BANK_DATE) {
          if (cmd.equals("&START&130")) {
            TMP = (String) part.get(4);
            if (TMP.equals("&END&"))
              message("ERROR - BANK DATE ''");
            else
              message("BANK DATE '" + TMP + "'");
          
          } else {
            message("ERROR - WE WERE WAITING FOR ACK BANK DATE HERE!");
          }
          
          LAST = CMD_NOP;
          continue;
        }

        // AFTER COMMIT
        if (LAST == CMD_COMMIT) {
          inCOMMIT = processCommit(cmd, part);

          if (inCOMMIT == COMMIT_TXN_COMPLETE) {
            // BINGO !!!
            message("COMMIT 'UPDATING FILES' 'TXN COMPLETE'");
            LAST = CMD_NOP;
//          inCOMMIT = COMMIT_NOP;
            canSave = true;
            
          } else if (inCOMMIT == COMMIT_TXN_VERIFIED) {
            LAST = CMD_NOP;
//          inCOMMIT = COMMIT_NOP;
            canSave = true;
            
          } else if (inCOMMIT == COMMIT_TXN_FAILED) {
            LAST = CMD_NOP;
//          inCOMMIT = COMMIT_NOP;
            SUMMA_FAILED++;
          }
          
          continue;
        }

        // ACK LOGIN
        // '&START&23'·7E·'131'·7E·'BURO.16'·7E·'1'·7E·'GBHUDEFR'·7E·'BNK_TREFI_HU0010001'·7C·'*'·7E·'HU0010001'·7E·7E·'0'·7E·'1'·7E·'1'·7E·'SUPER.USER'·7E· ...
        // '&START&30'·7E·'43'·7E·'PASSWORD TERMINATED, ENTER NEW ONE'·7E·7E·7E·'N'·7E·'Y'·7E·'16'·'&END&'
        // '&START&30'·FE·'35'·FE·'PLEASE REPEAT THE PASSWORD'·FE·FE·FE·'N'·FE·'Y'·FE·'16'·'&END&'
        if (LAST == CMD_LOGIN) {
          if (cmd.equals("&START&23")) {
            USER = (String) part.get(4);
            gLOGINS.add(USER);
            message(STR_LINE);
            message("* LOGIN '" + Tool.replace(USER, ".", "") + "' '" + PASSWORD + "'" + " at " + shortTimestamp(date));
            saveLoginFile(date, USER, PASSWORD);
            
          } else {
            message("LOGIN 'BEGIN' '" + Tool.replace(USER, ".", "") + "' '" + PASSWORD + "'");
            
            if (cmd.equals("&START&30")) {
              TMP = (String) part.get(4);
              message("POPUP '" + TMP + "'");
              
              if (TMP.equals("PLEASE REPEAT THE PASSWORD"))
                continue; // Keep the LAST value
            }
          }

          LAST = CMD_NOP;
          continue;
        }

      // Hexa value
      } else {
        // message("DROP - " + Tool.printList(part));
      }
    }
    
    if (canSave) {   
      saveTCRFile(BUILDER);
    }
  }
  
/*
  '&START&31'·7E·'17'·7E·'      VALIDATED'·7E·'2&END&'·                                                                      
  '&START&31'·7E·'2'·7E·7E·'1&END&'·                                                                                         
  '&START&31'·7E·'15'·7E·'TXN CANCELLED'·7E·'1&END&'·                                                                        
  '&START&22'·7E·'2140'·7E·'6'·7E·'6'·7E·7E·7E·'MATLMM'·7E·7E·7E·'11'·7E·'11'·7E·7E·'N'·7E·'N'·7E·7E·'MATURITY.DATE'·7E·'40'·7E ...
  '&START&11'·7E·'29'·7E·'MM1029300008'·7E·'MM/10293/00008'·7E·7E·'&END&'·                                                   
  '&START&9'·7E·'67'·7E·'0.93'·7E·'P91'·7E·'P91'·7E·7E·'LEC0087 No record in CITY.SPECIAL.TREATMENT for & '·7E·'93'·7F·'&END&'· 
  '&START&99'·7E·'59'·7E·'20 OCT 2010'·7E·'BURO.34'·7E·'5,te'·7E·'04 MAR 2011 14:21'·7E·'g15.0.00'·7E·'r06.004&END&'           

  '&START&31'·7E·'16'·7E·'UPDATING FILES'·7E·'2&END&'
  '&START&31'·7E·'14'·7E·'TXN COMPLETE'·7E·'1&END&'
  '&START&30' 7E '55' 7E '# Debit Acct. No...................' 7E 'PLEASE REKEY' 7E 7E 7E 'Y' 7E '16&END&'
  '&START&30' 7E '49' 7E 'INTEREST RATE MARGIN 1.11999995' 7E 'OVERRIDE' 7E 'Y_NO' 7E 7E 7E '2&END&'
  '&START&30'·7E·'38'·7E·'LIVE RECORD NOT CHANGED'·7E·7E·'CONTINUE'·7E·7E·7E·'20&END&'
  '&START&30'·FE·'33'·FE·'SECURITY.VIOLATION'·FE·FE·'CONTINUE'·FE·FE·FE·'20&END&' 
  '&START&30'·7E·'72'·7E·'(PD.ACCOUNTING)'·0D·00·0D·0A·'PD.RTN.UNABLE.LOAD.PD.AMOUNT.TYPE'·7E·'FATAL ERROR'·7E·'EXIT'·7E·7E·7E·'10'·'&END&'
*/  
  private int processCommit(String cmd, List<Object> content) throws RemoteException {

    Object o;
    String tmp;
    
    if (cmd.equals("&START&30")) {

      if ((o = Robot.getParam(content, DELIMITER_7E, 3)) != null) {
        if (o.equals("PLEASE REKEY")) {
          message("POPUP 'PLEASE REKEY' '" + Tool.replace((String) content.get(4), "'", "\'") + "'");
          return (inCOMMIT == COMMIT_SECOND_LEG ? COMMIT_SECOND_LEG : COMMIT_PLEASE_REKEY);
        }
      
        if (o.equals("OVERRIDE")) {
          message("POPUP 'OVERRIDE' '" + content.get(4) + "'");

          // Special commit failed
          if (content.get(4).equals("CHANGES NOT SAVED") || content.get(4).equals("VÁLTOZTATÁSOK NINCSENEK MENTVE")) {
            return (COMMIT_TXN_FAILED);
          }

          return (inCOMMIT == COMMIT_SECOND_LEG ? COMMIT_SECOND_LEG : COMMIT_OVERRIDE);
        }
        
        if (o.equals("FATAL ERROR")) {
          message("ERROR - 'FATAL ERROR' '" + Robot.getParam(content, DELIMITER_7E, 4) + "' !!!");
          return (COMMIT_TXN_FAILED);
        }
      }
      
      if ((o = Robot.getParam(content, DELIMITER_7E, 4)) != null) {     
        if (o.equals("CONTINUE")) {
          if (content.get(4) instanceof String) {
            tmp = (String) content.get(4);
            
            // Special commit failed
            if (tmp.equals("INPUT MISSING") || tmp.equals("ADAT HIÁNYZIK")) {
              message("POPUP 'CONTINUE' '" + tmp + "' *** TXN DROP ***");
              return (COMMIT_TXN_FAILED);
            }

            message("POPUP 'CONTINUE' '" + tmp + "'");
            
          } else {
            message("POPUP 'CONTINUE' '" + (Integer) content.get(4) + "'");
          }

          return (inCOMMIT == COMMIT_SECOND_LEG ? COMMIT_SECOND_LEG : COMMIT_CONTINUE);
        }
      }

      message("POPUP 'EXTRA' '" + content.get(4) + "'");
      return (inCOMMIT == COMMIT_SECOND_LEG ? COMMIT_SECOND_LEG : COMMIT_OVERRIDE);
    }
     
    if (cmd.equals("&START&31") && content.get(4) instanceof String) {
      tmp = (String) content.get(4);

      // Complete
      if (tmp.equals("TXN COMPLETE")) {
        SUMMA_COMMIT++;
        return (COMMIT_TXN_COMPLETE);
        
      // Canceled
      } else if (tmp.equals("TXN CANCELLED")) {
        if (liveNotChanged)
          message("WARN 'COMMIT' 'TXN CANCELLED'");
        else
          message("ERROR 'COMMIT' 'TXN CANCELLED'");
        
        return (COMMIT_TXN_FAILED);
        
      // Just blah blah message 
      } else {
 
        // Keep other messages
        if (tmp.equals("UPDATING FILES") || tmp.equals("      VALIDATED") || tmp.equals("     AUTHORISED"))
          return (inCOMMIT);

        if (tmp.startsWith("BUILDING PAGE"))
          return (inCOMMIT);
        
        message("COMMIT '" + Tool.leftTrim(tmp) + "'");
        
        if (tmp.equals("VERIFIED")) {
          return (COMMIT_TXN_VERIFIED);
        }

        return (inCOMMIT);
      }
    }

    // '&START&99' or any other '&START&' block in the respond
    return (inCOMMIT);
  }

  private String lookupFIELD(String number) throws RemoteException {

    if ((FIELD = FIELDS.get(VERSION_LAST + "_" + number)) == null) {
      FIELD = "'UNKNOWN'";
      message("ERROR - Unknown field number! - '" + VERSION_LAST + " (" + number + ")");
    }
    
    return (FIELD);
  }

  private String getSotParam(List<Object> list, int pos) {
    
    String ret;
    
    if (list.size() < (pos + 1))
      return ("");
    
    if (list.get(pos) instanceof String) {
      ret = Tool.replace((String) list.get(pos), "ü", "/");
      return (ret.equals("&EOT&") ? "" : ret);

    } else {
      return ("");
    }
  }
  
  /** True means drop it!  */ 
  private boolean cityFilter(boolean fromSave) throws RemoteException {

    // No filter
    if (isFILTER == false)
      return (false);

    // Drop if we are in See mode
//  if (MODE.equals("S"))
//    return (true);
    //

    if (fromSave && !ENV.equals(FILTER_ENVIROMENT.toUpperCase())) {
      message("*** TXN DROP *** Invalid enviroment filter!");
      SUMMA_TXN_DROP++;
      return (true);
    }

    if (fromSave && !Tool.contains(FILTER_USER_LIST, FILTER_USER_COPY)) {
      message("*** TXN DROP *** Invalid user filter! '" + FILTER_USER_COPY + "'");
      SUMMA_TXN_DROP++;
      return (true);
    }

    if (fromSave && !Tool.contains(FILTER_VERSION_LIST, FILTER_VERSION_COPY)) {
      message("*** TXN DROP *** Invalid version filter! '" + FILTER_VERSION_COPY + "'");
      SUMMA_TXN_DROP++;
      return (true);
    }

    // Okay
    return (false);
  }

  private void deleteAllTCR() throws RemoteException {

    String[] files = Tool.listDir(PATH, EXT_TCR);

    if (files != null && files.length > 0) {
      message(STR_WARN);
      message("DELETE ALL TCR FILES '" + files.length + "'");
    
      for (int i = 0; i < files.length; i++)
        Tool.delete(PATH + SEP + files[i], false);
    }
  }
  
  private boolean parseConfig() throws RemoteException {

    String line;
    String[] items;
    BufferedReader br = null;
    
    try {
      br = Tool.initFileReader(FILE_CONFIG);
      
    } catch (FileNotFoundException e) {
      message("FATAL ERROR - Can't find the TCR config file !!!");
      message(STR_PART);
      return (false);
    }

    while (true) {
      if ((line = Tool.nextLine(br)) == null) {
        break;
      }
      
      line = Tool.leftTrim(line);
      
      if (line.startsWith("#"))
        continue;
      
      if (line.length() < 4)
        continue;

      /////////////////////////////////////////////////////////////////
      // Parsing TCR config file parameters
      /////////////////////////////////////////////////////////////////
      
      if (line.startsWith("+s ")) {
        FILTER_SERVER = line.substring(3);
        message("FILTER SERVER '" + line + "'");
        continue;
      }

      if (line.startsWith("+p ")) {
        FILTER_PORT = line.substring(3);
        message("FILTER PORT '" + line + "'");
        continue;
      }

      if (line.startsWith("+e ")) {
        FILTER_ENVIROMENT = line.substring(3).toUpperCase();
        message("FILTER ENVIROMENT '" + line + "'");
        continue;
      }

      if (line.startsWith("+v ")) {
        VERSION = line.substring(3);
        //message("FILTER VERSION '" + line + "'");
        FILTER_VERSION_LIST.add(VERSION);
        continue;
      }

      if (line.startsWith("+u ")) {
        USER = line.substring(3);
        items = USER.split(",", -1);
        message("FILTER USER '" + line + "'");
        for (int i = 0; i < items.length; i++) {
          FILTER_USER_LIST.add(items[i]);
        }
        continue;
      }

      if (line.startsWith("-c ")) {
        CLIENT = line.substring(3);
        items = CLIENT.split(",", -1);
        message("FILTER CLIENT '" + line + "'");
        for (int i = 0; i < items.length; i++) {
          if (items[i].endsWith("*"))
            FILTER_CLIENT_LIST.add(items[i]);
          else
            FILTER_CLIENT_LIST.add(items[i] + "*");
        }
        continue;
      }
/*
      +FLAG_ONLY_PASS_3
      +FLAG_LOG_VERBOSE
                          
      -FLAG_SHOW_TAB
      +FLAG_SHOW_NEWLINE
      -FLAG_SHOW_CONTENT
      -FLAG_SHOW_UNKNOWN
*/
      if (line.startsWith("+FLAG_SHOW_NEWLINE")) {
        FLAG_SHOW_NEWLINE = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_SHOW_NEWLINE")) {
        FLAG_SHOW_NEWLINE = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_NO_PASS_3")) {
        FLAG_NO_PASS_3 = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_NO_PASS_3")) {
        FLAG_NO_PASS_3 = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_SAVE_LOG")) {
        FLAG_SAVE_LOG = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_SAVE_LOG")) {
        FLAG_SAVE_LOG = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_USE_PORT_NUMBER")) {
        FLAG_USE_PORT_NUMBER = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_USE_PORT_NUMBER")) {
        FLAG_USE_PORT_NUMBER = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_DELETE_TEMP")) {
        FLAG_DELETE_TEMP = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_DELETE_TEMP")) {
        FLAG_DELETE_TEMP = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_DO_BACKUP")) {
        FLAG_DO_BACKUP = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_DO_BACKUP")) {
        FLAG_DO_BACKUP = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_SAVE_DROP")) {
        FLAG_SAVE_DROP = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("-FLAG_SAVE_DROP")) {
        FLAG_SAVE_DROP = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }

      if (line.startsWith("+FLAG_SAVE_DEV_VIEW")) {
        FLAG_SAVE_DEV_VIEW = true;
        message("FILTER FLAG '" + line + "'");
        continue;
      }
      
      if (line.startsWith("-FLAG_SAVE_DEV_VIEW")) {
        FLAG_SAVE_DEV_VIEW = false;
        message("FILTER FLAG '" + line + "'");
        continue;
      }
      
      message (STR_WARN);
      message("FATAL ERROR - Syntax error in this config line - '" + line + "'");
      
      return (false);

    } // LOOP

    message (STR_WARN);
    message("FILTER VERSION COUNTER '" + FILTER_VERSION_LIST.size() + "'");
    message (STR_WARN);
    
    if (FILTER_SERVER.equals("?")) {
      message("FATAL ERROR - No server name specified!");
      return (false);
    }

    if (FILTER_ENVIROMENT.equals("?")) {
      message("FATAL ERROR - No enviroment name specified!");
      return (false);
    }
    
    if (FLAG_NO_PASS_3 && FLAG_ONLY_PASS_3) {
      message("FATAL ERROR - FLAG_NO_PASS_3 and FLAG_ONLY_PASS_3 can't be true together!");
      return (false);
    }

    return (true);
  }

  private void init(String[] args) {

    try {
      
      PATH = new File("").getAbsolutePath();
      
      if (args.length != 2) {
        Tool.err(STR_PART);
        Tool.err("CONVERT RAW GLOBUS TELNET COMMUNICATION DATA");
        Tool.err(STR_PART);
        Tool.err("Usage: java -jar TCRConvert.jar {config-file} {input-file}");
        isFatal = true;
        return;
      }
      
      FILE_CONFIG = args[0];
      FILE_INPUT = args[1];

      //////////////////////////////////////////////////////////////////
      
      startTime = Tool.getTime();
      
      if (contains(FILE_INPUT, SEP)) {
        PATH = new File(FILE_INPUT).getParent();
      }

      if (new File(PATH).exists() == false) {
        Tool.err("Error: The path does not exist! '" + PATH + "'");
        isFatal = true;
        return;
      }

      // Init the log files (message() calls only from this point!)
      FILE_LOG = PATH + SEP + FILE_LOG;
      FILE_ERROR_LOG = PATH + SEP + FILE_ERROR_LOG;

      Tool.delete(FILE_LOG, true);
      Tool.delete(FILE_ERROR_LOG, true);
      //
      
      message(STR_WARN);
      message("PARAM CONFIG FILE '" + FILE_CONFIG + "'");
      message("PARAM INPUT FILE '" + FILE_INPUT + "'");

      if (isFatal)
        return;
        
      message_("CONVERT RAW GLOBUS TELNET COMMUNICATION DATA");
      message ("PATH '" + PATH + "'");
      message ("LOG FILE '" + FILE_LOG.substring(FILE_LOG.lastIndexOf(SEP) + 1) + "'");
      message ("CONVERT DATE '" + Tool.getDate("yyyy.MM.dd HH:mm (EEEEEEEE)") + "'");
          
      message (STR_WARN);
      message ("*** PARSING TCR CONFIG ***");
      message (STR_WARN);

      if (parseConfig() == false) {
        isFatal = true;
        return;
      }
          
      message ("JAVA NAME '" + System.getProperty("java.runtime.name") + "'");
      message ("JAVA HOME '" + System.getProperty("java.home") + "'");
      message ("JAVA RUNTIME '" + System.getProperty("java.runtime.version") + "'");
    //message ("JAVA TMPDIR '" + System.getProperty("java.io.tmpdir") + "'");

      deleteAllTCR();

    } catch (RemoteException e) {
      e.printStackTrace();
    }
  }

/*
 * Saving special UNIX shell scripts for convert raw capture data 
 */
  private static void saveUnixConvertScript() {
/*    
    #!/usr/bin/ksh

    gunzip r6.record.011.gz
    sudo /usr/sbin/tcpdump -tttt -vKXS -r r6.record.011 > r6.capture.011.txt
*/
    StringBuilder sb1 = new StringBuilder();
    StringBuilder sb2 = new StringBuilder();
    
    sb1.append("#!/usr/bin/ksh\n\n");
    sb1.append("gunzip r6.record.0.gz\n");
    sb1.append("sudo /usr/sbin/tcpdump -tttt -vKXS -r r6.record.0 > r6.capture.00.txt" + "\n\n");

    for (int i = 1; i < 61; i++) {
      sb1.append("gunzip r6.record.0" + i + ".gz" + "\n");
      sb1.append("sudo /usr/sbin/tcpdump -tttt -vKXS -r r6.record.0" + i + " > r6.capture.0" + i + ".txt" + "\n\n");
    }
/*    
    #!/usr/bin/ksh
    
    cat r6.capture.01.txt >>r6.capture.txt
*/    
    sb2.append("#!/usr/bin/ksh\n\n");
    
    for (int i = 0; i < 62; i++) {
      sb2.append("cat r6.capture.0" + i + ".txt" + " >>r6.capture.txt\n");
    }

    try {
      Tool.save(new File("").getAbsolutePath() + SEP + "release" + SEP + "convert.sh", sb1.toString());
      Tool.save(new File("").getAbsolutePath() + SEP + "release" + SEP + "concat.sh" , sb2.toString());
      
    } catch (IOException e) {
      e.printStackTrace();
    }
  }
  
  public boolean contains(String base, String pattern) {
    
    if (base == null || pattern == null)
      return (false);
      
    return (base.indexOf(pattern) != -1);
  }
  
  ///////////////////////////////////////////////////////////////////
  // MAIN
  ///////////////////////////////////////////////////////////////////

  public static void main(String[] args) {

//  saveUnixConvertScript();

    TCRConvert parser = new TCRConvert();

    parser.init(args);
    
    parser.doPass1();
    parser.doPass2();
    parser.doPass3();

    System.exit(isFatal ? -1 : 0);
  }

  /** Write your pass #2 custom filter here (return null will drop the packet!) */
  private String customContentFilter(String data) {

    //data = Tool.replace(data, "0D", "@@");
    return (data);
  }
}

