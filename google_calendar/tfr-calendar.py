#!/usr/bin/env python3

import yaml
import argparse
import datetime

from gcal_api import GoogleCalendarAPI, GCAL_DATE_FORMAT


def init_args():
    # Define command line arguments
    ap = argparse.ArgumentParser(description='View/edit TFR schedule. Uses Google Calendar API, '
                                             'which requires the relevant API access to be enabled. '
                                             'Usage: ./tfr-calendar.py -a -r2')
    # Only one argument in the group is accepted
    ap.add_argument('-l', '--list', dest='list', action='store_true', default=True,
                    help="List future events")
    ap.add_argument('-L', dest='list', action='store_false',
                    help="Do not list future events")
    ap.add_argument('-a', '--add', dest='add', action='store_true', default=False,
                    help="Add new events after the last existing one")
    ap.add_argument('-d', '--delete', dest='delete', action='store_true',
                    default=False, help="Delete all future events")
    ap.add_argument('-r', '--repeat', dest='repeat', type=int, default=1,
                    help="Number of times to assign TFR duty to each engineer")
    ap.add_argument('-s', '--secret-file', dest='secret_file', type=str,
                    default='client_secret.json',
                    help='JSON file with the client secret (acquired from Google)')
    ap.add_argument('-c', '--credentials-file', dest='credentials_file',
                    type=str, default='credentials.json',
                    help='Credentials JSON. The file will be generated on first run'
                         ' - browser will open automatically for you to grant the '
                         'necessary permissions)')
    ap.add_argument('--calendar', dest='calendar',
                    default='Tesla Point Of Contact', help="Calendar name")
    ap.add_argument('-t', '--tfr-file', dest='tfr_file', default='tfr.yaml',
                    help="YAML file with TFR engineers")
    ap.add_argument('-n', '--dry-run', dest='dry_run', action='store_true',
                    help="Go through the motions, but don't update the calendar")
    return ap.parse_args()


def events_create(cal_id: str, start: datetime.datetime, attendees: {},
                  repetitions=1, term_days=7):
    for repetition in range(repetitions):
        for name, email in attendees.items():
            summary = 'TFR - '+name
            start_str = start.date().isoformat()
            end_str = (start + datetime.timedelta(
                days=term_days)).date().isoformat()
            print("Scheduling: '{}', email: {}, start: {}, end: {}".format(
                summary, email, start_str, end_str))
            cal_api.event_insert(cal_id, email, summary, start_str, end_str)
            start = start + datetime.timedelta(days=term_days)


def events_delete(cal_id: str, events: list):
    for event in events:
        cal_api.event_delete(cal_id, event['id'])


def events_print(event_list):
    for event in event_list:
        fields = ['id', 'status', 'summary', 'start', 'end', 'attendees']
        event_desc = ""
        for field in fields:
            try:
                event_desc = "{} {}: {}".format(event_desc, field, event[field])
            except KeyError:
                pass
        print("Event:{}".format(event_desc))


def get_events_errors(event_list) -> []:
    errors = []
    last_event = None

    for event in event_list:
        fields = ['id', 'status', 'summary', 'start', 'end', 'attendees']
        event_desc = ""

        for field in fields:
            try:
                event_desc = "{} {}: {}".format(event_desc, field, event[field])
            except KeyError:
                print("WARN: Missing value for key {}".format(field))
        # print("Event:{}".format(event_desc))

        if last_event:
            last_event_end = datetime.datetime.strptime(
                last_event['end']['date'], GCAL_DATE_FORMAT)
            next_event_start = datetime.datetime.strptime(
                event['start']['date'], GCAL_DATE_FORMAT)
            if last_event_end != next_event_start:
                errors.append("Adjacent events don't have adjacent date.\n"
                              "Event 1: '{}' ({}) end:{}.\n"
                              "Event 2: '{}' ({}) start:{}.".format(
                    last_event['summary'], last_event['id'], last_event['end'],
                    event['summary'], event['id'], event['start']))

        last_event = event

        if not len(event['attendees']):
            errors.append("Event {} ({}) doesn't have an assignee".format(
                event['summary'], event['id']))
    return errors


def load_attendees() -> {}:
    attendees = dict()
    with open(args.tfr_file, 'r') as tfr_file:
        participants = yaml.load(tfr_file)

    for participant in participants:
        attendees[participant['name']] = participant['email']

    return attendees


def last_monday():
    date = datetime.datetime.today()
    weekday = date.weekday()

    sunday = 6
    if weekday != sunday:
        date -= datetime.timedelta(days=weekday)

    return date


args = init_args()

# Initialize the Calendar API
cal_api = GoogleCalendarAPI(args.secret_file, args.credentials_file, args.dry_run)

# Get the TFR calendar
cal = cal_api.get_calendar(args.calendar)
print("Calendar '{}' id: {}".format(args.calendar, cal['id']))

# Get the calendar events ordered by date
events = cal_api.events_list(cal_id=cal['id'],
                             start_utc=datetime.datetime.utcnow(),
                             order_by='startTime')

if args.list:
    print("Future events:")
    events_print(events)

warnings = get_events_errors(events)
for warning in warnings:
    print("WARN: {}".format(warning))

last_event = None

if args.delete:
    print("Cleaning {} future events in calendar {}".format(
        len(events), cal['id']))
    events_delete(cal['id'], events)

if events:
    last_event = events[-1]
    print("Last event in '{}' calendar: '{}' ends on {}".format(
        args.calendar, last_event['summary'], last_event['end']['date']))
else:
    print("No future events found - assuming last Sunday")

    last_event = {'end': {'date': '{}'.format(last_monday().date())}}
    events = [last_event]


if args.add:
    attendees = load_attendees()
    print(attendees)

    print("Updating the rotation - repeated {} times".format(args.repeat))

    start_dt = datetime.datetime.strptime(events[-1]['end']['date'],
                                          GCAL_DATE_FORMAT)
    events_create(cal['id'], start=start_dt, attendees=attendees,
                  repetitions=args.repeat)
