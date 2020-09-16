
package ca.toronto.api.oidc.utils;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.Date;

/**
 * @author rzheng City of Toronto. Jul 26, 2016
 */
public class DateUtil {

	public static boolean isLessThan(Date executedTime, int interval) {
		Calendar cal = Calendar.getInstance();
		cal.setTime(executedTime);
		cal.add(Calendar.SECOND, interval - 10);
		if (new Date().before(cal.getTime())) {
			return true;
		} else {
			return false;
		}
	}

	public static boolean isMoreThanHours(Date currentTime, Date previousTime, int hours) {
		long diff = currentTime.getTime() - previousTime.getTime();
		if (diff >= (long)hours * 60 * 60 * 1000) {
			return true;
		} else {
			return false;
		}
	}

	public static String formatDate(Date date, String format) {
		SimpleDateFormat dt = new SimpleDateFormat(format);
		return dt.format(date);
	}

	public static Date toDate(String date, String format) throws ParseException {
		SimpleDateFormat dt = new SimpleDateFormat(format);
		return dt.parse(date);
	}
}
