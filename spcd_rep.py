from datetime import datetime, timedelta


def spaced_repetition_cumulative(start_date_str, cumulative_days):
    start_date = datetime.strptime(start_date_str, "%Y-%m-%d")

    dates = [start_date]

    for days in cumulative_days:
        review_date = start_date + timedelta(days=days)
        dates.append(review_date)

    return dates


# Take user input
user_input = input("Enter start date (YYYY-MM-DD) or 't' for today: ").strip().lower()

# Handle today's date
if user_input == 't':
    start_date_str = datetime.now().strftime("%Y-%m-%d")
else:
    start_date_str = user_input

# Example intervals
cumulative = [1, 3, 7, 14, 28]

# Generate schedule
schedule = spaced_repetition_cumulative(start_date_str, cumulative)

# Print schedule
for i, date in enumerate(schedule):
    if i == 0:
        print(f"Initial study: {date.strftime('%d/%m/%Y')}")
    else:
        print(f"Review {i}: {date.strftime('%d/%m/%Y')}")
