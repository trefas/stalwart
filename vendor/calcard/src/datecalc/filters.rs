/*
 * SPDX-FileCopyrightText: 2021 Fredrik Meringdal, Ralph Bisschops <https://github.com/fmeringdal/rust-rrule>
 *
 * SPDX-License-Identifier: Apache-2.0 OR MIT
 */

use super::{
    iterinfo::IterInfo,
    rrule::{NWeekday, RRule},
};

type RRuleFilter = &'static dyn Fn(&IterInfo, usize, &RRule) -> bool;

const FILTERS: [RRuleFilter; 7] = [
    &is_filtered_by_month,
    &is_filtered_by_week_number,
    &is_filtered_by_weekday,
    &is_filtered_by_neg_weekday,
    &is_filtered_by_easter,
    &is_filtered_by_month_day,
    &is_filtered_by_year_day,
];

pub(crate) fn is_filtered(ii: &IterInfo, current_day: usize) -> bool {
    let rrule = ii.rrule();
    FILTERS
        .into_iter()
        .any(|filter| filter(ii, current_day, rrule))
}

fn is_filtered_by_month(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    if rrule.by_month.is_empty() {
        return false;
    }

    let current_month = ii.month_mask()[current_day];
    !rrule.by_month.contains(&current_month)
}

fn is_filtered_by_week_number(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    if rrule.by_week_no.is_empty() {
        return false;
    }

    matches!(ii.week_no_mask(), Some(week_no_mask) if week_no_mask[current_day] == 0)
}

fn is_filtered_by_weekday(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    let mut by_weekday_every_week_only = rrule
        .by_weekday
        .iter()
        .filter_map(|by_weekday| match by_weekday {
            // Get only `Every` occurrences.
            NWeekday::Every(weekday) => Some(weekday.num_days_from_monday()),
            NWeekday::Nth(_, _) => None,
        })
        .peekable();

    // Check if empty
    if by_weekday_every_week_only.peek().is_none() {
        return false;
    }

    let current_weekday = ii.weekday_mask()[current_day];
    !by_weekday_every_week_only.any(|el| el == current_weekday)
}

fn is_filtered_by_neg_weekday(ii: &IterInfo, current_day: usize, _rrule: &RRule) -> bool {
    if let Some(neg_weekday_mask) = ii.neg_weekday_mask() {
        if neg_weekday_mask.is_empty() {
            return false;
        }

        let current_neg_weekday = neg_weekday_mask[current_day];
        current_neg_weekday == 0
    } else {
        false
    }
}

fn is_filtered_by_easter(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    if rrule.by_easter.is_none() {
        return false;
    }
    match i32::try_from(current_day) {
        Ok(current_day) => {
            !matches!(ii.easter_mask(), Some(easter_mask) if easter_mask.contains(&current_day))
        }
        _ => true,
    }
}

fn is_filtered_by_month_day(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    if rrule.by_month_day.is_empty() && rrule.by_n_month_day.is_empty() {
        return false;
    }

    let current_month_day = ii.month_day_mask()[current_day];
    let current_n_month_day = ii.neg_month_day_mask()[current_day];
    let filtered_by_month_day = !rrule.by_month_day.contains(&current_month_day);
    let filtered_by_n_month_day = !rrule.by_n_month_day.contains(&current_n_month_day);

    filtered_by_month_day && filtered_by_n_month_day
}

fn is_filtered_by_year_day(ii: &IterInfo, current_day: usize, rrule: &RRule) -> bool {
    if rrule.by_year_day.is_empty() {
        return false;
    }

    let current_day = match i16::try_from(current_day) {
        Ok(current_day) => current_day,
        _ => return true,
    };

    let year_len = (ii.year_len()) as i16;
    let next_year_len = (ii.next_year_len()) as i16;

    if current_day < year_len {
        !rrule.by_year_day.contains(&(current_day + 1))
            && !rrule.by_year_day.contains(&(current_day - year_len))
    } else {
        !rrule.by_year_day.contains(&(current_day + 1 - year_len))
            && !rrule
                .by_year_day
                .contains(&(current_day - next_year_len - year_len))
    }
}
