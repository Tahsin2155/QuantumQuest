from datetime import datetime, timedelta

def spaced_repetition_cumulative(start_date_str, cumulative_days):
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")
    
    dates = [start_date]
    
    for days in cumulative_days:
        review_date = start_date + timedelta(days=days)
        dates.append(review_date)

    return dates


# Example
cumulative = [1, 3, 7, 14, 28]
schedule = spaced_repetition_cumulative(datetime.now().date().strftime("%Y-%m-%d"), cumulative)

for i, date in enumerate(schedule):
    if i == 0:
        print(f"Initial study: {date.strftime('%d/%m')}")
    else:
        print(f"Review {i}: {date.strftime('%d/%m')}")