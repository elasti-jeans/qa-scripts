## Dependencies
```
. venv/bin/activate
pip3 install --upgrade google-api-python-client oauth2client pyyaml
```

## Example commands

List future schedules
```
./tfr-calendar.py
```

Add one entry/person based on defaults
```
./tfr-calendar.py -a -t tfr.yaml -n
```

Add 2 entries/person using custom secret/credentials/persons
```
./tfr-calendar.py -a -r 1 -s client_secret.json -c credentials.json -t tfr.yaml -n
```

