//! Calendar arithmetic for signed request times and credential expiry.

/// `unix_seconds` as `YYYYMMDDTHHMMSSZ`.
pub(crate) fn amz_date(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let second_of_day = unix_seconds % 86_400;
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_index = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_index + 2) / 5 + 1;
    let month = if month_index < 10 {
        month_index + 3
    } else {
        month_index - 9
    };
    let year = year_of_era + era * 400 + u64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}T{:02}{:02}{:02}Z",
        second_of_day / 3_600,
        second_of_day % 3_600 / 60,
        second_of_day % 60
    )
}

/// The unix time of `YYYY-MM-DDTHH:MM:SS` followed by `Z`, with or without
/// a fractional second. Anything else is `None`.
pub(crate) fn parse_utc(text: &str) -> Option<u64> {
    let (stamp, rest) = text.split_at_checked(19)?;
    let fraction = rest.strip_suffix('Z')?;
    let fraction_ok = fraction.is_empty()
        || fraction
            .strip_prefix('.')
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit()));
    let bytes = stamp.as_bytes();
    let separators = bytes[4] == b'-'
        && bytes[7] == b'-'
        && bytes[10] == b'T'
        && bytes[13] == b':'
        && bytes[16] == b':';
    if !fraction_ok || !separators {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u64> {
        let digits = stamp.get(range)?;
        digits
            .bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| digits.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let adjusted_year = year - u64::from(month <= 2);
    let era = adjusted_year / 400;
    let year_of_era = adjusted_year - era * 400;
    let month_index = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * month_index + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    let days = (era * 146_097 + day_of_era).checked_sub(719_468)?;
    Some(days * 86_400 + hour * 3_600 + minute * 60 + second)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_times_are_formatted_as_the_service_expects() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(1_440_938_160), "20150830T123600Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(amz_date(1_790_000_000), "20260921T141320Z");
    }

    #[test]
    fn expiry_times_round_trip_and_reject_other_forms() {
        for unix in [
            0_u64,
            951_782_400,
            1_440_938_160,
            1_790_000_000,
            4_102_444_799,
        ] {
            let stamp = amz_date(unix);
            let text = format!(
                "{}-{}-{}T{}:{}:{}Z",
                &stamp[0..4],
                &stamp[4..6],
                &stamp[6..8],
                &stamp[9..11],
                &stamp[11..13],
                &stamp[13..15]
            );
            assert_eq!(parse_utc(&text), Some(unix), "{text}");
        }
        assert_eq!(parse_utc("2015-08-30T12:36:00.123Z"), Some(1_440_938_160));
        for invalid in [
            "",
            "2015-08-30T12:36:00",
            "2015-08-30T12:36:00+00:00",
            "2015-08-30 12:36:00Z",
            "2015-13-30T12:36:00Z",
            "2015-08-30T24:36:00Z",
            "2015-08-30T12:36:00.Z",
            "1969-12-31T23:59:59Z",
            "20150830T123600Z",
        ] {
            assert_eq!(parse_utc(invalid), None, "{invalid}");
        }
    }
}
