package org.peter.util;

/*
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.Transport;
import javax.mail.internet.MimeMessage;

import com.sun.org.apache.xml.internal.serialize.OutputFormat;
import com.sun.org.apache.xml.internal.serialize.XMLSerializer;
import hu.fot.testManager.core.datapool.Datapool;
import hu.fot.testManager.core.datapool.Datarow;
import hu.fot.util.xml.XmlHelper;
*/

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import java.io.File;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.rmi.RemoteException;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Properties;

/**
 * Usefull Static Common Methods (in the test robot development).
 * 
 * @author loolek@gmail.com
 *
      $$$$$$$$$$$$$$$$$$ $$$  $$$   $     $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
      $$$$$$$$$$$$$$   $$    $$         $$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$
       $    $$$$$$$$   $$$$           $  $$  $$$$$$$$$$$$$$$$$$$$$$    $$
             $$$$$$$$$$$$$$$         $$ $$$$$$$$$$$$$$$$$$$$$$$$$$$   $
              $$$$$$$$$$$$ $           $$$$$$$$$$$$$$$$$$$$$$$$$$$$
              $$$$$$$$$$$            $$  $$$$  $$ $$$$$$$$$$$$$$$  $
               $$$$$$$$$             $$$$     $$$$$$$$$$$$$$$$$ $ $
                 $$$                $$$$$$$$$$$$$$$$$$$$$$$$$$$
                   $$$$             $$$$$$$$$$$$$    $$   $$$  $
                       $$$$$$        $$$$$$$$$$$$          $  $
                       $$$$$$$$$         $$$$$$            $ $$   $$$
                        $$$$$$$          $$$$$$ $              $$$$$
                         $$$$$            $$$$  $            $$$$$$$$
                         $$$                $$                $$  $$$     $
                        $$                                               $
 */
public class Robot {

  private static String[] CURRENCY = { 
    "AUD","BGN","BRD","BRL","CAD","CHF","CNY","CZK","DEM","DKK","ECD",
    "EEK","EUR","GBP","HRK","HUF","ISK","JPY","KRW","KWD","LTL","LVL",
    "MXN","NOK","NZD","PLN","ROL","RON","RSD","RUB","SEK","SIT","SKK",
    "TRY","USD"
  };

  /////////////////////////////////////////////////////////////////////////
  
  /** 
   * GLOBUS enviroment data (inner class) 
   */
  public static class ENV {

    public String id, server, env, envpass, version, user, userpass, userId;

    public ENV() {
      id = version = Tool.STR_EMPTY;
    }
    
    public ENV(String id, String server, String env, String envpass, String version, String user, String userpass) {
      this.id = id;
      this.server = server;
      this.env = env;
      this.envpass = envpass;
      this.version = version;
      this.user = user;
      this.userpass = userpass;
      this.userId = makeGlobusUserId(user);
    }
  }

  /////////////////////////////////////////////////////////////////////////////
  // Using the javax.mail package for sendind email by SMTP protocol
  /////////////////////////////////////////////////////////////////////////////
/*
  private static String MAIL_SERVER = "gandalf.local";
  
  public static void setMailServer(String server) {
    
    if (server != null)
      MAIL_SERVER = server;
  }
  
  // SMTP send mail  
  public static void sendMail(String from, String to, String subject, String body) throws MessagingException {

    Properties props = new Properties();
    props.put("mail.smtp.host", MAIL_SERVER);
    props.put("mail.from", from);
    
    Session session = Session.getInstance(props, null);

    MimeMessage msg = new MimeMessage(session);
    msg.setFrom();
    msg.setRecipients(Message.RecipientType.TO, to);
    msg.setSubject(subject);
    msg.setSentDate(new Date());
    msg.setText(body);
    
    Transport.send(msg);
  }
*/ 
  
  /////////////////////////////////////////////////////////////////////////////////////////////
  // '&START&7'·FE·'26647'·FE·'REF.NO'·FD·'REF.NO............'·FD·FE· ... ·FE·FF·FF

  public static List<Object> getBlock(List<Object> content, int seq) {
    
    return (getBlock(content, 0xFE, seq));
  }
  
  /** Collect the values between the given positon marks */ 
  public static List<Object> getBlock(List<Object> content, int sep, int seq) {
    
    int counter = 0;
    List<Object> part = new ArrayList<Object>();
    
    for (int i = 0; i < content.size(); i++) {
      
      // Collect between FE 'REF.NO' FD 'REF.NO............' FD FE ... FE ... FF FF
      if (content.get(i) instanceof Integer) {
        // Separator
        if ((Integer) content.get(i) == sep) { // 0xFE or 0xFF or 0xFD or 0x7E
          counter++;
        } else if (counter == seq) {
          part.add(content.get(i));
        }
      // String
      } else {
        if (counter > seq)
          break;
      
        if (counter == seq)
          part.add(content.get(i));
      }
    } 
    
    return (counter >= seq ? part : null);    
  }

  /** Get the seq value from the list (seq starts with 0) */
  public static Object getParam(List<Object> list, int sep, int seq) {
    
    List<Object> part;
    
    part = getBlock(list, sep, seq);
    
    if (part == null)
      return (null);
    
    return (part.size() == 1 ? part.get(0) : null);   
  }
  
  public static List<Object> cutList(List<Object> list, int from, boolean block) {

    boolean flag = false;
    List<Object> part = new ArrayList<Object>();
    
    for (int a = 0; a < list.size(); a++) {
      Object o = list.get(a);
      
      if (a == from)
          flag = true;

      // Build a new list
      if (flag) {
        part.add(o);
        
        if (block && o instanceof String && (((String) o).indexOf("&END&") != -1 || ((String) o).indexOf("&EOT&") != -1))
          return (part);
      }
    }
    
    return (part);
  }
  
  public static List<Object> cutList(List<Object> list, String from) {

    boolean flag = false;
    List<Object> tmp = new ArrayList<Object>();
    
    for (int a = 0; a < list.size(); a++) {
      Object o = list.get(a);
      
      if (o instanceof String) {
        if (((String) o).equals(from))
          flag = true;
      }
      // Build a new list
      if (flag)
        tmp.add(o);
    }
    
    return (tmp);
  }
  
  public static String getLastString(List<Object> list) {
    
    Object o;
    String last = null;
    
    if (list != null) {
      for (int i = list.size() - 1; i > -1; i--) {
        if ((o = list.get(i)) instanceof String) {
          last = (String) o;
          break;
        }
      }
    }
    
    return (last);
  }
  
  /////////////////////////////////////////////////////////////////////////
/*
  public static long nextSEQ(Datapool dp, String id) throws RemoteException {

    Datarow row = dp.cut(id);
    long value = Long.parseLong((String) row.value(1)) + 1;
    row.setValue(1, "" + value);
    dp.put(row);
      
    return (value);
  }
*/
 /** 
  * Makes a GlobusID from TTSOR5 to TTSOR.5, from BURO22 to BURO.22, from T-U201940 to T-U.201940 
  */
  public static String makeGlobusUserId(String user) {
    
    String result = "";
    boolean flag = true;
    
    if (user.indexOf(".") != -1)
      return (user);
    
    for (int i = 0; i < user.length(); i++) {
      char ch = user.charAt(i);
      if (Tool.isStrictlyNumber(ch) && flag) {
        result = Tool.concatChar(result, '.');
        flag = false;
      }
      
      result = Tool.concatChar(result, ch);
    }
    
    return (result);
  }

  public static String getWorkspace() {
    return (new File("").getAbsoluteFile().getParent() + Tool.SEP);
  }

  public static boolean isCurrency(String value) {

    for (int i = 0; i < CURRENCY.length; i++) {
      if (value.startsWith(CURRENCY[i])) {
        return (true);
      }
    }

    return (false);
  }

  public static String[] getCurrencies() {
    return(CURRENCY);
  }

  public static boolean isDouble(String value) {
    
    return (Tool.isDouble(GLOBUS_get_number(value)));
  }

  public static double getDouble(String value) {
    
    return (Double.parseDouble(GLOBUS_get_number(value)));
  }

  /** 
   * Convert a special Globus Number string 
   * like 'USD******100,000.23-' to '-100000.23'
   */
  public static String GLOBUS_get_number(String value) {

    // .8732
    if (value.startsWith(".")) {
      if (Tool.isDouble("0" + value))
        return ("0" + value);
      else
        return (value);
    } 

    String tmp = Tool.replace(value, "*", Tool.STR_EMPTY);

    if (isCurrency(tmp)) {
      tmp = tmp.substring(3);
    }

    if (tmp.endsWith("-")) {
      tmp = tmp.substring(0, tmp.length() - 1);
      tmp = "-" + tmp;
    }

    // 1.8732
    if (Tool.contains(tmp, '.') == 1 && tmp.indexOf(",") == -1) {
      int digit = tmp.length() - tmp.indexOf('.') - 1;
      if (digit != 3 && tmp.charAt(tmp.length() - 1) != '-') {
        return (tmp);
      }
    }

    // 1,8732
    if (Tool.contains(tmp, ',') == 1 && tmp.indexOf(".") == -1) {
      int digit = tmp.length() - tmp.indexOf(',') - 1;
      if (digit != 3 && tmp.charAt(tmp.length() - 1) != '-') {
        tmp = Tool.replace(tmp, ",", ".");
        return (tmp);
      }
    }

    // if ends with .0 or .00
    if (tmp.length() >= 3 && (tmp.charAt(tmp.length() - 3) == '.' || tmp.charAt(tmp.length() - 2) == '.')) {
      tmp = Tool.replace(tmp, ",", Tool.STR_EMPTY);
      return (tmp);
    }
    
    // if ends with ,0 or ,00
    if (tmp.length() >= 3 && (tmp.charAt(tmp.length() - 3) == ',' || tmp.charAt(tmp.length() - 2) == ',')) {
      tmp = Tool.replace(tmp, ".", Tool.STR_EMPTY);
      tmp = Tool.replace(tmp, ",", ".");
      return (tmp);
    }

    // Clear all possible left thousand marks
    tmp = Tool.replace(tmp, ",", Tool.STR_EMPTY);
    tmp = Tool.replace(tmp, ".", Tool.STR_EMPTY);
    
    return (tmp);
  }
  
  /** 
   * Convert a special Globus Interface Number 
   * like '100208USD101344,' to '100208USD101344.00'
   */
  public static String GLOBUS_get_if_number(String value) {

    int i;
    String date, currency, number;  

    if (value.length() < 10)
      return (value); // no change
    
    for (i = 0; i < 6; i++) {
      if (Tool.isNumber(value.charAt(i)) == false)
        return (value); // no change
    }

    date = value.substring(0, 6);
    currency = value.substring(6, 9);
    
    for (i = 0; i < CURRENCY.length; i++) {
      if (currency.equals(CURRENCY[i])) {
        break;
      }
    }

    if (i == CURRENCY.length)
      return (value); // no change

    number = value.substring(9);

    if (number.endsWith(","))
      number = number.concat("00");

    return (date + currency + GLOBUS_get_number(number));
  }

  /////////////////////////////////////////////////////////////////////////////
  
  /* Calculating the size of an object */
  public static int serialisedSize(Object object) {

    CountingOutputStream out;
    ObjectOutputStream stream;

    out = new CountingOutputStream();

    try {
      stream = new ObjectOutputStream(out);
      stream.writeObject(object);

    } catch (Exception ex) {
      ex.printStackTrace();
      return (-1);
    }

    return (out.sizeof);
  }

  private static class CountingOutputStream extends OutputStream {

    int sizeof = 0;

    public void write(int b) {
      sizeof++;
    }
  }
  
  /////////////////////////////////////////////////////////////////////////////
  // Using org.apache.xml stuff here (for encoding use "UTF-8" "WINDOWS-1250")
  /////////////////////////////////////////////////////////////////////////////
  
  public static Document createDocument() throws SAXException {

    try {
      DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
      return (dbf.newDocumentBuilder().newDocument());

    } catch (ParserConfigurationException e) {
      throw new SAXException();
    }
  }

/*
  public static String printNode(Node node) {
  
    if (node == null) {
      return ("(null)");
    }
    
    return (serialize((Element) node));
  }

    
  public static String serialize(Document document) {
    return (serialize(document, null));
  }

  public static String serialize(Document document, String encoding) {

    StringWriter sw = new StringWriter();

    OutputFormat of = new OutputFormat();
    of.setIndenting(true);
    of.setLineSeparator(System.getProperty("line.separator"));
    of.setIndent(4);
    if (encoding != null)
      of.setEncoding(encoding);

    XMLSerializer serializer = new XMLSerializer(of);
    serializer.startNonEscaping();
    serializer.setOutputCharStream(sw);

    try {
      serializer.asDOMSerializer().serialize(document);

    } catch (IOException e) {
      e.printStackTrace();
    }

    return (sw.toString());
  }
*/  

//
// static {
//   Timer timer = new Timer("TikiTaki", true);
//   TimerTask task = new timerTask();
//   timer.schedule(task, 1000, 120000);
// }
//  
// private static class timerTask extends TimerTask {
//
//   @Override
//   public void run() {
//     tik-tak  
//   }
// }

  /////////////////////////////////////////////////////////////////////////////
  // Main entry for testing the tools
  /////////////////////////////////////////////////////////////////////////////

  public static void main(String[] args) {

    System.out.println(Robot.getDouble("HUF****100,12-"));
    System.out.println(Robot.getDouble("1.8732"));
    System.out.println(Robot.getDouble("6.755,00"));
  }
}

