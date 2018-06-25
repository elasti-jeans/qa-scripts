import datetime


from apiclient.discovery import build
from httplib2 import Http
from oauth2client import file, client, tools


GCAL_DATE_FORMAT = '%Y-%m-%d'
SCOPES = 'https://www.googleapis.com/auth/calendar'


class GoogleCalendarAPI:
    def __init__(self, secret_file='client_secret.json',
                 cred_file='credentials.json', dry_run=False):
        # Init service

        store = file.Storage(cred_file)
        creds = store.get()
        if not creds or creds.invalid:
            flow = client.flow_from_clientsecrets(secret_file, SCOPES)
            creds = tools.run_flow(flow, store)
        self.service = build('calendar', 'v3', http=creds.authorize(Http()))
        self.dry_run = dry_run

    def get_calendar(self, calendar_name: str):
        page_token = None
        calendar = None
        while True:
            calendar_list = self.service.calendarList().list(
                pageToken=page_token).execute()
            for cal_list_entry in calendar_list['items']:
                if cal_list_entry['summary'] == calendar_name:
                    calendar = cal_list_entry
                    print("Found calendar: {}".format(cal_list_entry['summary']))
            page_token = calendar_list.get('nextPageToken')
            if not page_token:
                break

        if not calendar:
            raise Exception("Calendar {} not found".format(CALENDAR_NAME))

        return calendar


    def events_list(self, cal_id: str, start_utc: datetime.datetime, order_by='startTime'):
        page_token = None
        all_events = []

        dt_rfc3339 = start_utc.isoformat()+'Z'

        while True:
            events = self.service.events().list(calendarId=cal_id,
                                           pageToken=page_token,
                                           timeMin=dt_rfc3339,
                                           orderBy=order_by,
                                           singleEvents=True).execute()
            for event in events['items']:
                # print("Found event: {}".format(event['summary']))
                all_events.append(event)
            page_token = events.get('nextPageToken')
            if not page_token:
                break

        return all_events


    def event_insert(self, cal_id: str, attendee: str, summary: str,
                     start_date: str, end_date: str):
        event = {
          'summary': summary,
          'start': {
            # 'dateTime': start_date,  # '2015-05-28T09:00:00-07:00'
            'date': start_date,  # '2015-05-28T09:00:00-07:00'
            'timeZone': 'UTC',
          },
          'end': {
            # 'dateTime': end_date,  # '2015-05-28T17:00:00-07:00'
            'date': end_date,  # '2015-05-28T17:00:00-07:00'
            'timeZone': 'UTC',
          },
          'attendees': [
            {'email': attendee},
          ],
          'reminders': {
            'useDefault': False,
            'overrides': [
              {'method': 'email', 'minutes': 12 * 60},
            ],
          },
        }

        if not self.dry_run:
            event = self.service.events().insert(
                calendarId=cal_id, body=event).execute()
            print('Event created: %s' % (event.get('htmlLink')))
        else:
            print("WARN: Dry run - skipping calendar update")
