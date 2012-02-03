package org.peter.util;

import java.awt.Toolkit;
import java.awt.datatransfer.Clipboard;
import java.awt.datatransfer.StringSelection;
import java.awt.datatransfer.Transferable;

import java.io.BufferedInputStream;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.PrintWriter;
import java.io.RandomAccessFile;
import java.io.Reader;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.UnsupportedEncodingException;

import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.MissingResourceException;
import java.util.Properties;
import java.util.Random;
import java.util.ResourceBundle;
import java.util.StringTokenizer;
import java.util.TreeSet;
import java.util.Vector;
import java.util.jar.JarEntry;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Usefull Common Static Methods (using only the standart java runtime API)
 * 
 * @author loolek@gmail.com
 *
          |  \ \ | |/ /
          |  |\ `' ' /
          |  ;'aorta \      / , pulmonary
          | ;    _,   |    / / ,  arteries
 superior | |   (  `-.;_,-' '-' , vena cava
          | `,   `-._       _,-'_
          |,-`.    `.)    ,<_,-'_, pulmonary
         ,'    `.   /   ,'  `;-' _,  veins
        ;        `./   /`,    \-'
        | right   /   |  ;\   |\
        | atrium ;_,._|_,  `, ' \
        |        \    \ `       `,
        `      __ `    \   left  ;,
         \   ,'  `      \,  ventricle
          \_(            ;,      ;;
          |  \           `;,     ;;
 inferior |  |`.          `;;,   ;' vena cava 
          |  |  `-.        ;;;;,;'
          |  |    |`-.._  ,;;;;;'
          |  |    |   | ``';;;'  FL
                  aorta
  */

public class Tool {

	public final static String EOL = "\n";
	public final static String LF = "\n";
	public final static String CRLF = "\r\n";
	public final static String BEEP = "•";

	public final static String SEP = File.separator;

	public final static String STR_EMPTY = "";
	public final static String STR_LINE = Tool.makeSeparator(65);
	public final static String STR_COMMENT = Tool.makeSeparator(65, '*');

	public final static String STR_READ_ENCODE = "Cp1250";
	public final static String STR_WRITE_ENCODE = "Cp1250";

	/////////////////////////////////////////////////////////////////////////////

	public static long getTime() {
		return (System.nanoTime());
	}

	/** The return value is in seconds. */
	public static double elapsed(long startTime) {
		return ((double) (((System.nanoTime() - startTime) * 1e-6) / 1000));
	}

	public static long getCalendarTime() {
		Calendar c = Calendar.getInstance();
		return (c.getTimeInMillis());
	}

	/** The return value is in seconds. */
	public static double elapsedCalendarTime(long startTime) {
		return ((double) (getCalendarTime() - startTime) / 1000);
	}

	public static void sleep(int millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
		}
	}

	public static void beep() {
		System.out.print(BEEP);
	}

	/////////////////////////////////////////////////////////////////////////////
	
	private static Random random = null;

	public static int random(int ceiling) {
		if (random == null)
			random = new Random(System.nanoTime());
		return (random.nextInt(ceiling + 1));
	}

	public static int getRandom(int MIN, int MAX) {

		while (true) {
			int rand = Tool.random(MAX);
			if (rand >= MIN && rand <= MAX)
				return (rand);
		}
	}

	/////////////////////////////////////////////////////////////////////////////

	public static boolean contains(List<String> list, String pattern) {

		String tmp;
		
		if (list == null || pattern == null)
			return (false);

		for (int i = 0; i < list.size(); i++) {
			tmp = list.get(i);
			if (tmp.endsWith("*")) {
				tmp = tmp.substring(0, tmp.length() - 1);
				if (pattern.startsWith(tmp))
					return (true);
			} else {
				if (pattern.equals(tmp))
					return (true);
			}
		}

		return (false);
	}

	public static boolean contains(String[] list, String pattern) {

		return (contains(list, pattern, true));
	}

	public static boolean contains(String[] list, String pattern, boolean fullMatch) {

		if (list == null || pattern == null)
			return (false);

		for (int i = 0; i < list.length; i++) {
			if (fullMatch) {
				if (list[i].equalsIgnoreCase(pattern))
					return (true);
			} else {
				if (list[i].indexOf(pattern) != -1)
					return (true);
			}
		}

		return (false);
	}

	public static boolean contains(String base, String pattern) {
    
    if (base == null || pattern == null)
      return (false);
	      
    return (base.indexOf(pattern) != -1);
  }
	
	public static boolean contains(String line, String[] patternList) {

		if (line == null || patternList == null)
			return (false);

		for (int i = 0; i < patternList.length; i++) {
			if (line.indexOf(patternList[i]) != -1)
				return (true);
		}

		return (false);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static BufferedReader initReader(String data) {
		
		return (new BufferedReader(new StringReader(data)));
	}

	public static BufferedReader initFileReader(String name) throws FileNotFoundException {
		
		return (new BufferedReader(new FileReader(name)));
	}

	public static void closeFileReader(BufferedReader br) throws IOException {
		
		br.close();
	}

	public static String nextLine(BufferedReader br) {
		
		try {
			return (br.readLine());
			
		} catch (IOException e) {
			e.printStackTrace();
		}

		return (null);
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static String getStackTrace(Throwable ex) {

		if (ex == null) {
			StackTraceElement[] stack = Thread.currentThread().getStackTrace();

			String tmp = "";
			for (int i = 0; i < stack.length; i++)
				tmp = tmp + " " + stack[i].toString() + "\r\n";

			return (tmp);
		}

		StringWriter sw = new StringWriter();
		PrintWriter pw = new PrintWriter(sw, true);

		ex.printStackTrace(pw);

		pw.flush();
		sw.flush();

		return (sw.toString());
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static String specTrim(String line, String delimiter, int startPos) {

		String tmp = "";
		boolean flag = true;

		for (int i = 0; i < line.length(); i++) {
			if (flag && Character.isWhitespace(line.charAt(i)))
				continue;

			tmp = concatChar(tmp, line.charAt(i));
			flag = false;
		}

		return (tmp);
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static String leftTrim(String line) {

		String tmp = "";
		boolean flag = true;

		for (int i = 0; i < line.length(); i++) {
			if (flag && Character.isWhitespace(line.charAt(i)))
				continue;

			tmp = concatChar(tmp, line.charAt(i));
			flag = false;
		}

		return (tmp);
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static String replace(String string, String oldPattern, String newPattern) {

		StringBuffer sb = null;
		
		int end, start = 0;
		int len = oldPattern.length();

		while (true) {

			end = string.indexOf(oldPattern, start);

			if (end == -1) {
				if (start == 0)
					return (string);

				/* A maradék sztring véget is hozzá adom. */
				sb.append(string.substring(start));
				break;
			}

			if (sb == null)
				sb = new StringBuffer(128);

			sb.append(string.substring(start, end));
			sb.append(newPattern);
			start = end + len;
		}

		return (sb.toString());
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * A kapott sztringben kicserél minden beirt \n \r és \t karakter sort
	 * a nativ változatra (pld. a \n = 0x0A).
	 */
	public static String controlParser(String string) {

		string = replace(string, "\\n", "\n");
		string = replace(string, "\\r", "\r");
		string = replace(string, "\\t", "\t");

		return (string);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * Ha a kapott sztring egyenlõ "true", "igen", "yes", "on" vagy "1" akkor igazzal tér vissza,
	 * minden más esetben hamissal. A java -ban lévõ boolean parser túl szigorú, ha már
	 * egy más karakter is van a sztringben akkor egybõl exception -t dob.
	 */
	public static boolean parseBoolean(String value) {

		if (value.equalsIgnoreCase("on") || value.equalsIgnoreCase("true") || value.equalsIgnoreCase("igen") || value.equalsIgnoreCase("yes") || value.equalsIgnoreCase("1")) {
			return (true);
		} else {
			return (false);
		}
	}

	/////////////////////////////////////////////////////////////////////////////

	public static void fprintf(FileOutputStream stream, String string) throws IOException {
		stream.write(string.getBytes(STR_WRITE_ENCODE));
	}

	public static void fprintf(RandomAccessFile stream, String string) throws IOException {
		stream.writeBytes(string);
	}

	public static void printf(String string) {
		System.out.print(string);
	}

	public static void out(String string) {
		System.out.print(string);
	}

	public static void err(String string) {
		System.err.println(string);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * Betölt egy resource .class vagy .property file-t, a megadott Locale
	 * szerinti kiterjesztéssel. pld. menu_hu_HU.properties
	 */
	public static ResourceBundle loadResource(String baseName) throws MissingResourceException {
		
		ClassLoader cl = Thread.currentThread().getContextClassLoader();
		ResourceBundle bundle = ResourceBundle.getBundle(baseName, Locale.getDefault(), cl);

		return (bundle);
	}

	public static Properties loadProperties(String fileName) throws FileNotFoundException, IOException {

		Reader r;

		Properties props = new Properties();
		props.load(r = new FileReader(fileName));
		r.close();
		
		return (props);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static Method findMethod(Object obj, String methodName) {

		Method[] methods = obj.getClass().getMethods();

		for (int i = 0; i < methods.length; i++) {

			if (methods[i].getName().equals(methodName)) {
				return (methods[i]);
			}
		}

		return (null);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * A kapott nativ nevet pld. product_id java osztály névvé konvertálja
	 * ProductId. Egy prefixet is megadhatunk akkor az kerül elõre pld.
	 * setProductId
	 */
	public static String getJavaName(String name, String prefix) {

		StringTokenizer st = new StringTokenizer(name, "_");

		while (st.hasMoreTokens()) {

			String token = st.nextToken();
			String firstChar = token.substring(0, 1).toUpperCase();

			token = token.substring(1);
			prefix = prefix.concat(firstChar + token);
		}

		return (prefix);
	}

	public static String getNativeName(String name) {

		String result = "";

		char[] dim = name.toCharArray();
		dim[0] = Character.toLowerCase(dim[0]);

		for (int i = 0; i < dim.length; i++) {

			if (Character.isUpperCase(dim[i]))
				result = result.concat("_");

			result = concatChar(result, Character.toLowerCase(dim[i]));
		}

		return (result);
	}

	public static String concatChar(String str, char c) {

		String letter = String.valueOf(c);
		return (str.concat(letter));
	}

	public static String makeSeparator(int len) {

		String line = "";

		for (int i = 0; i < len; i++)
			line = concatChar(line, '-');

		return (line);
	}

	public static String makeSeparator(int len, char ch) {

		String line = "";

		for (int i = 0; i < len; i++)
			line = concatChar(line, ch);

		return (line);
	}

	/////////////////////////////////////////////////////////////////////////////
	// List<> manipulation, building a new List from a given String value

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

	/////////////////////////////////////////////////////////////////////////////

	/** WARNING: This method's using the space ' ' character for tokenizing the line! */
	public static String getXMLField(String line, String field) {

		StringTokenizer st = new StringTokenizer(line, " ");

		while (st.hasMoreTokens()) {
			String token = st.nextToken();

			if (token.startsWith(field + "=") == true) {
				token = token.substring(token.indexOf("\"") + 1);
				token = token.substring(0, token.indexOf("\""));
				return (token);
			}
		}

		return (null);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static List<String> getJarEntryNames(String fileName) {

		List<String> list = new ArrayList<String>();

		try {
			FileInputStream fis = new FileInputStream(fileName);
			JarInputStream jin = new JarInputStream(new BufferedInputStream(fis));
			JarEntry entry;

			while ((entry = jin.getNextJarEntry()) != null) {
				list.add(entry.getName());
			}

		} catch (Exception e) {
			e.printStackTrace();
		}

		return (list);
	}

	/////////////////////////////////////////////////////////////////////////////
	// FILE TOOLS
	/////////////////////////////////////////////////////////////////////////////

	/**
	 * Egy file név sztringbõl csinál egy új sztringet, amiben a file
	 * kiterjesztése már a megadott "extension" lesz.
	 * 
	 * pld. Tool.changeExtension(file.getPath(), "xml");
	 */
	public static String changeExtension(String name, String extension) {

		int endIndex;

		if ((endIndex = name.lastIndexOf('.')) == -1) {
			return (name + "." + extension);
		}

		return (name.substring(0, endIndex + 1) + extension);
	}

	/////////////////////////////////////////////////////////////////////////////
	
  public static String getPath(File file) {

    if (file == null)
      return ("");

    return (file.getParent());
  }

  public static String getPath(String fileName) {

    if (fileName == null)
      return ("");

    return (new File(fileName).getParent());
  }

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * Returns the size of the file or null if its not exists.
	 */
	public static Long size(String name) {

		File file = new File(name);

		if (file.exists() == false)
			return (null);

		return (file.length());
	}

	public static String load(String name) throws IOException {
		return (load(name, -1));
	}

	public static String load(File file) throws IOException {
		return (load(file, -1));
	}

	public static String load(String name, int len) throws IOException {

		File file = new File(name);

		if (file.length() < len)
			len = (int) file.length();

		FileInputStream stream = new FileInputStream(file);

		byte[] buffer = load(stream, len);

		return (new String(buffer, STR_READ_ENCODE));
	}

	public static String load(File file, int len) throws IOException {

		FileInputStream stream = new FileInputStream(file);

		byte[] buffer = load(stream, len);

		return (new String(buffer, STR_READ_ENCODE));
	}

	public static byte[] load(InputStream stream, int len) throws IOException {

		byte[] buffer;

		if (len == -1) {
			buffer = new byte[stream.available()];
			stream.read(buffer);
		} else {
			buffer = new byte[len];
			stream.read(buffer, 0, len);
		}

		stream.close();

		return (buffer);
	}

	public static void save(String name, String buffer) throws IOException {

		save(name, buffer.getBytes(STR_WRITE_ENCODE));
	}

	public static void save(String name, byte[] buffer) throws IOException {
		
		FileOutputStream fos;

		createDirs(name);
		
		fos = new FileOutputStream(name);
		fos.write(buffer);
		fos.flush();
		fos.close();
	}

	public static void append(String name, String buffer) throws IOException {

		append(name, buffer, true);
	}

	public static void append(String name, String buffer, boolean close) throws IOException {
		
		FileOutputStream fos;

		createDirs(name);
		
		fos = new FileOutputStream(name, true);
		fos.write(buffer.getBytes(STR_WRITE_ENCODE));
		
		if (close) {
			fos.flush();
			fos.close();
		}
	}

	/**
	* A java csak létezõ könyvtárba tud menteni! Ezért ez a hívás rekurzivan
	* létrehozza a szükséges könyvtárakat a megadott file név alapján.
	*/
	public static void createDirs(String fileName) {
		
		File file = new File(fileName);
		File parentdir = parent(file);

		if (!parentdir.exists()) {
			createDirs(parentdir.getAbsolutePath()); // RECURSIVE !!
			parentdir.mkdir();
		}
	}

	/**
	* File.getParent() null -t add vissza, ha a file nevet könyvtárnév nélkül
	* adjuk meg, vagy a gyökér könyvtárban van.
	*/
	public static File parent(File f) {
		
		String dirName = f.getParent();

		if (dirName == null) {
			if (f.isAbsolute()) {
				return new File(File.separator);
			} else {
				return new File(System.getProperty("user.dir"));
			}
		}

		return new File(dirName);
	}

	/**
	 * Ha a backup flag true, akkor elõbb csinál egy másolatott a 
	 * file -ról '~' jellel a végén. Ezután letörli a file -t.
	 */
	public static void delete(String fileName, boolean backup) {

		delete(new File(fileName), backup);
	}

	/**
	 * Ha a backup flag true, akkor elõbb csinál egy másolatott a 
	 * file -ról '~' jellel a végén. Ezután letörli a file -t.
	 */
	public static void delete(File file, boolean backup) {

		if (backup) {

			File f = new File(file.getPath() + "~");

			if (f.exists())
				f.delete();

			file.renameTo(f);

		} else {

			file.delete();
		}
	}

	public static void move(String src, String dest) throws IOException {
		
		move(new File(src), new File(dest));
	}

	public static void move(File src, File dest) throws IOException {

		if (dest.exists())
			delete(dest, false);

		createDirs(dest.getAbsolutePath());
		
		if (src.renameTo(dest) == false) {
			throw new IOException("File move failed: '" + src.getName() + "'");
		}
	}

	/**
	* Átmásol egy fájlt a kért helyre (és ha kell, elõbb létrehozza a 
	* szükséges szülõ könyvtárakat is).
	*/
	public static void copy(File src, File dest) throws IOException {

		FileInputStream source = null;
		FileOutputStream destination = null;
		
		byte[] buffer;
		int bytes_read;

		if (!src.exists())
			throw new IOException("Source not found: " + src);

		if (!src.canRead())
			throw new IOException("Source is unreadable: " + src);

		if (src.isFile()) {
			if (!dest.exists()) {
				File parentdir = parent(dest);

				if (!parentdir.exists()) {
					parentdir.mkdir();
				}
			} else if (dest.isDirectory()) {
				dest = new File(dest + File.separator + src);
			}
		} else if (src.isDirectory()) {
			if (dest.isFile()) {
				throw new IOException("Cannot copy directory " + src + " to file " + dest);
			}

			if (!dest.exists()) {
				dest.mkdir();
			}
		}

		if (src.isFile()) {
			try {
				source = new FileInputStream(src);
				destination = new FileOutputStream(dest);
				buffer = new byte[1024];

				while (true) {
					bytes_read = source.read(buffer);

					if (bytes_read == -1)
						break;

					destination.write(buffer, 0, bytes_read);
				}
			} finally {
				if (source != null)
					source.close();

				if (destination != null)
					destination.close();
			}
		} else if (src.isDirectory()) {
			String targetfile;
			String target;
			String targetdest;
			String[] files = src.list();

			for (int i = 0; i < files.length; i++) {
				targetfile = files[i];
				target = src + File.separator + targetfile;
				targetdest = dest + File.separator + targetfile;

				if ((new File(target)).isDirectory()) {
					// RECURSIVE !!
					copy(new File(target), new File(targetdest));
					//
				} else {
					try {
						source = new FileInputStream(target);
						destination = new FileOutputStream(targetdest);
						buffer = new byte[1024];

						while (true) {
							bytes_read = source.read(buffer);

							if (bytes_read == -1)
								break;

							destination.write(buffer, 0, bytes_read);
						}
					} finally {
						if (source != null)
							source.close();

						if (destination != null)
							destination.close();
					}
				}
			}
		}
	}

	public static void log(FileOutputStream stream, String message) throws IOException {

		stream.write((message + "\r\n").getBytes(STR_WRITE_ENCODE));

		if (message.toLowerCase().indexOf("error") != -1)
			System.err.println(message);
		else
			System.out.println(message);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * A belsõ java tárolású string -et consol encoding -ra alakítja át,
	 * és kiírja a DOS képernyõre.
	 */
	public static void consolePrint(String line) {

		PrintStream ps = null;

		try {
			ps = new PrintStream(System.out, true, "Cp852");

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		ps.println(line);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	* Converts a byte to a java inner char type (UTF) with the default Charset.
	*/
	public static char decodeByteToChar(byte b) {

		CharsetDecoder cd = Charset.defaultCharset().newDecoder();
		cd.reset();

		ByteBuffer bb = ByteBuffer.wrap(new byte[] { b }, 0, 1);
		CharBuffer cb = CharBuffer.wrap(new char[1]);

		cd.decode(bb, cb, true);

		return (((char[]) cb.array())[0]);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static String escapeStringReverse(String line) {
		
		return (line.replaceAll("&amp;", "&").replaceAll("&quot;", "\"").replaceAll("&apos;", "'").replaceAll("&lt;", "<").replaceAll("&gt;", ">"));
	}

	/**
	* Replaces the '&amp;', '&quot;', '&lt;' and '&gt;'
	* characters with the appropriate character escapes, so that the returned
	* string can be used as an XML attribute value or content.
	*/
	public static String escapeString(String str) {

		if (str == null)
			return null;

		StringBuilder buf = new StringBuilder();
		int strlen = str.length();

		for (int i = 0; i < strlen; ++i) {
			char c = str.charAt(i);
			switch (c) {
			case '&':
				buf.append("&amp;");
				break;
			case '"':
				buf.append("&quot;");
				break;
			case '\'':
				buf.append("&apos;");
				break;
			case '<':
				buf.append("&lt;");
				break;
			case '>':
				buf.append("&gt;");
				break;
			case '\t':
				// less than 32, but can be included literally
				buf.append(c);
				break;
			case '\n':
				buf.append("\\n"); // &#x0A;
				break;
			case '\r':
				buf.append("\\r"); // &#x0D;
				break;
			case 0:
				buf.append("`00`");
				break;
			default:
				if (c < 32) {
					// use character reference
					buf.append("&#").append((int) c).append(';');
				} else {
					buf.append(c);
				}
			}
		}

		return buf.toString();
	}

	/////////////////////////////////////////////////////////////////////////////

	public static String URLDecode(String url) {
		
		try {
			return (java.net.URLDecoder.decode(url, "ISO8859_2"));

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return (url);
	}

	public static String URLEncode(String url) {
		
		try {
			return (java.net.URLEncoder.encode(url, "ISO8859_2"));

		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}

		return (url);
	}

	/////////////////////////////////////////////////////////////////////////////

	/**
	 * A belsõ java tárolású sztringet UTF-8 formátumba alakítja
	 */
	public static String getUTF(String str) {

		String tmp = null;

		try {
			tmp = new String(str.getBytes("UTF-8"));
		} catch (UnsupportedEncodingException ex) {
			ex.printStackTrace();
		}

		return (tmp);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static String randomString(int len) {

		char[] str = new char[len];

		for (int i = 0; i < len; i++) {
			str[i] = (char) (((int) (Math.random() * 26)) + (int) 'A');
		}

		return (new String(str, 0, len));
	}

	/////////////////////////////////////////////////////////////////////////////

	/** Keep only the number characters */
	public static String numberFilter(String buffer) {

		String number = "";

		char[] dim = buffer.toCharArray();

		for (int i = 0; i < dim.length; i++) {

			if (isNumber(dim[i]))
				number = concatChar(number, dim[i]);
		}

		return (number);
	}

	/////////////////////////////////////////////////////////////////////////////

	private static int exitCode = -1;

	/** This variable is NOT thread save. Use only in one thread context !!! */
	public static int getExitCode() {
		return (exitCode);
	}

	/** exec("cmd /c diff.exe -i -u d:\\test1.xml d:\\test2.xml") */
	public static StringBuilder exec(String command, boolean waitExit) throws IOException, InterruptedException {

		Process pr = Runtime.getRuntime().exec(command);

		BufferedReader input = new BufferedReader(new InputStreamReader(pr.getInputStream()));
		BufferedReader error = new BufferedReader(new InputStreamReader(pr.getErrorStream()));

		String line;
		StringBuilder builder = new StringBuilder(128);

		while ((line = input.readLine()) != null) {
			builder.append(line + "\r\n");
		}

		while ((line = error.readLine()) != null) {
			builder.append(line + "\r\n");
		}

		if (waitExit)
			exitCode = pr.waitFor();

		return (builder);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static String match(String regExp, String value) {

		if (regExp.startsWith("#RE")) {
			Pattern p = Pattern.compile("#RE_(.*)", Pattern.CASE_INSENSITIVE);
			Matcher m = p.matcher(regExp);
			if (m.matches())
				regExp = m.group(1);
		}

		Pattern p = Pattern.compile(regExp);
		Matcher m = p.matcher(value);
		
		if (m.matches())
			return (m.group(0)); // BINGO
		else
			return (value);
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static String[] listDir(String filePath, String extension) {
		
		return (listDir(filePath, extension, null, false));
	}

	public static String[] listDir(String filePath, String extension, boolean isRecursive) {
		
		return (listDir(filePath, extension, null, isRecursive));
	}

	public static String[] listDir(String filePath, String extension, String[] filterList, boolean isRecursive) {
		
		ArrayList<String> list = new ArrayList<String>();
		File dir = new File(filePath);
		String[] content = dir.list();
		
		if (content == null)
			return (null);
		
		l1: for (int i = 0; i < content.length; i++) {
			File entry = new File(filePath + Tool.SEP + content[i]);
			if (entry.isDirectory() == false) {
				if (extension == null || content[i].endsWith(extension) == true) {
					if (filterList != null) {
						for (int a = 0; a < filterList.length; a++) {
							if (content[i].indexOf(filterList[a]) != -1 || filePath.indexOf(filterList[a]) != -1)
								continue l1;
						}
					}

					if (isRecursive)
						list.add(filePath + Tool.SEP + content[i]);
					else
						list.add(content[i]);
				}
			} else {
				if (isRecursive) { // RECURSIVE CALL!!!
					try {
						String[] subDirList = listDir(entry.getCanonicalPath(), extension, filterList, true);
						for (int a = 0; subDirList != null && a < subDirList.length; a++) {
							list.add(subDirList[a]);
						}
					} catch (IOException e) {
						e.printStackTrace();
					}
				}
			}
		}

		if (list.size() == 0) {
			return (null);
		}

		Collections.sort(list);
		return (String[]) list.toArray(new String[0]);
	}

	/////////////////////////////////////////////////////////////////////////////

	public static Date makeDate(int year, int month, int day) {

		Calendar c = new GregorianCalendar();

		month -= 1;

		c.set(year, month, day, 0, 0, 0);

		return (c.getTime());
	}
	
	public static Date makeDate(int year, int month, int day, int hour, int minute, int second, int millisecond) {

		Calendar c = new GregorianCalendar();

		month -= 1;

		c.set(year, month, day, hour, minute, second);
		c.set(Calendar.MILLISECOND, millisecond);
		
		return (c.getTime());
	}

	public static Date makeDate(String year, String month, String day, String hour, String minute, String second, String millisecond) {

		Calendar c = new GregorianCalendar();

		int m = Integer.parseInt(month) - 1;

		c.set(Integer.parseInt(year), m, Integer.parseInt(day), Integer.parseInt(hour), Integer.parseInt(minute), Integer.parseInt(second));
		c.set(Calendar.MILLISECOND, Integer.parseInt(millisecond));
		
		return (c.getTime());
	}
	
	/////////////////////////////////////////////////////////////////////////////
	
	/** 112427 */
	public static void waitUntil(long time) {
	  
	  long current;
	  
	  while (true) {
	    current = Long.parseLong(Tool.getDate("HHmmss"));
	    
	    if (time - current > 0)
	      sleep(1000);
	    else
	      break;
	  }
	}
	
	//////////////////////////////////////////////////////////////////////////// 
	/**
	--------------------------------------------------------------------------- 
	  Letter, Date or Time Component, Presentation, Examples
	 ---------------------------------------------------------------------------
	  G Era designator Text AD
	  y Year Year 1996; 96
	  M Month in year Month July; Jul; 07
	  w Week in year Number 27
	  W Week in month Number 2
	  D Day in year Number 189
	  d Day in month Number 10
	  F Day of week in month Number 2
	  E Day in week Text Tuesday; Tue
	  a Am/pm marker Text PM
	  H Hour in day (0-23) Number 0
	  k Hour in day (1-24) Number 24
	  K Hour in am/pm (0-11) Number 0
	  h Hour in am/pm (1-12) Number 12
	  m Minute in hour Number 30
	  s Second in minute Number 55
	  S Millisecond Number 978
	  z Time zone General time zone Pacific Standard Time; PST; GMT-08:00
	  Z Time zone RFC 822 time zone -0800
	 ---------------------------------------------------------------------------
	  example: getDate("yyyy-MM-dd HH:mm:ss.SSS")
	  more: http://java.sun.com/javase/6/docs/api/java/text/SimpleDateFormat.html
	 ---------------------------------------------------------------------------
	 */
	public static String getDate(String pattern) {
		
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
		return (simpleDateFormat.format(new Date()));
	}

	public static String getDate(Date date, String pattern) {
		
		SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
		return (simpleDateFormat.format(date));
	}

 	/////////////////////////////////////////////////////////////////////////////

	/** Return a formater string like '0.00' */
	public static String makeDecimalFormat(int size) {
		
		String format = "0.";
		for (int i = 0; i < size; i++)
			format = Tool.concatChar(format, '0');
		
		return (format);
	}

	public static boolean isDouble(String value) {
		
		try {
			Double.parseDouble(value);
			return (true);
			
		} catch (NumberFormatException e) {
			return (false);
		}
	}

	/** 
	 * If the object is null or if the object is a String with size 0 or the value "null"
	 * then this function returns true.
	 */
	public static boolean isNull(Object object) {

		if (object == null) {
			return (true);
		}

		if (object instanceof String) {
			if ((((String) object).equals("null") == true) || (((String) object).length() == 0)) {
				return (true);
			}
		}

		return (false);
	}

	public static boolean isNumber(char ch) {

		return (((ch >= '0') && (ch <= '9')) || ((ch == ',') || (ch == '.') || (ch == '-') || (ch == '+')));
	}

	public static boolean isStrictlyNumber(char ch) {

		return (((ch >= '0') && (ch <= '9')));
	}

	public static boolean isWindowsPlatform() {

		String os = System.getProperty("os.name");

		if ((os != null) && os.startsWith("Windows")) {
			return (true);
		} else {
			return (false);
		}
	}

	public static boolean isContains(String data, char ch) {
		
		for (int i = 0; i < data.length(); i++) {
			if (data.charAt(i) == ch)
				return (true);
		}
		return (false);
	}

	public static int contains(String data, char ch) {
		int cnt = 0;

		for (int i = 0; data != null && i < data.length(); i++) {
			if (data.charAt(i) == ch)
				cnt++;
		}
		return (cnt);
	}

	/////////////////////////////////////////////////////////////////////////////

	@SuppressWarnings("unchecked")
	public static StringBuilder printMap(Map map) {

		StringBuilder sb = new StringBuilder();
		Iterator i = map.values().iterator();

		while (i.hasNext()) {
			sb.append(i.next().toString());
		}

		return (sb);
	}

	@SuppressWarnings("unchecked")
	public static String printHashMap(Map map, boolean withValue) {

		if (map == null)
			return ("(null)");
		
		StringBuilder sb = new StringBuilder();

		Iterator iterator = new TreeSet(map.keySet()).iterator();
		while (iterator.hasNext()) {
			String key = iterator.next().toString();

			if (withValue) {
				String value = "(null)";
				Object object = map.get(key);
				if (object != null)
					value = object.toString();

				sb.append(key + " = '" + value + "'\r\n");

			} else {
				sb.append("'" + key + "'\r\n");
			}
		}
		
		return (sb.toString());
	}

	@SuppressWarnings("unchecked")
	public static String printVector(Vector map) {

		StringBuilder sb = new StringBuilder();
		Iterator iterator = map.iterator();

		while (iterator.hasNext()) {
			sb.append("'" + iterator.next().toString() + "'\r\n");
		}
		
		return (sb.toString());
	}

	public static String printList(List<Object> list) {
		
		int number;
		StringBuilder sb = new StringBuilder();
		
		for (int i = 0; i < list.size(); i++) {
			Object o = list.get(i);
			if (o instanceof Integer) {
				if ((number = (Integer) list.get(i)) < 256)
					sb.append(String.format("%02X ", number));
				else
					sb.append(String.format("%0X ", number));

			} else
				sb.append("'" + list.get(i) + "' ");
		}
		return (sb.toString());
	}

	public static String printString(String[] dim) {
		
		StringBuilder sb = new StringBuilder();
		for (int i = 0; i < dim.length; i++) {
			sb.append("'" + dim[i] + "'\r\n");
		}
		return (sb.toString());
	}

	/**
	* AAAX -> AAAY -> AAAZ -> AABA -> AABB -> AABC -> etc.
	*/
	public static String increment(String value) {

		String result = "";
		boolean flag = true;
		int len = value.length();
		for (int i = 0; i < len; i++) {
			int num = ((int) value.charAt(len - i - 1));

			if (flag && num == 90) { // 'Z'
				result = 'A' + result;
			} else {
				if (flag) {
					result = ((char) (num + 1)) + result;
					flag = false;
				} else {
					result = ((char) num) + result;
				}
			}
		}

		return (result);
	}

	public static String getTimeString(String longTime) {
		
		SimpleDateFormat sdf = new SimpleDateFormat("HH:mm:ss.SSS");
		Date date = new Date();
		date.setTime(Long.parseLong(longTime));

		return (sdf.format(date));
	}

	/////////////////////////////////////////////////////////////////////////////
	
	public static void writeToClipboard(String text) {
		
		Clipboard cb = Toolkit.getDefaultToolkit().getSystemClipboard();
		Transferable data = new StringSelection(text);
		cb.setContents(data, null);
	}

	/////////////////////////////////////////////////////////////////////////////
	// Main entry for testing the tools
	/////////////////////////////////////////////////////////////////////////////

	public static void main(String[] args) {

		System.out.println(getDate("yyyy-MM-dd HH:mm:ss.SSS"));
		
		System.out.println(new File("").getAbsoluteFile().getParent() + SEP);
	}
}

