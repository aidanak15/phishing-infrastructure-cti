# Optional follow-up: verify a clearly labeled local message-to-click sequence

**Status: not yet performed.** This is a local educational demonstration, not a phishing attempt. It does not reproduce message delivery, impersonation, or credential theft.

1. In Terminal, from the existing `week6/simulation` directory, start the educational server with `python3 -m http.server 8088 --bind 127.0.0.1` and leave the process running. If the port is busy, stop the existing lab server first.
2. Open `simulation/training_message.html` **locally** in a browser. Save a screenshot showing its explicit educational label and localhost link. Do not send it as an email.
3. Click the localhost link once and confirm the educational `index.html` loads. Note the wall-clock time.
4. Capture the resulting new `GET /index.html` log entry from the server Terminal and note its timestamp. Stop the server with Ctrl+C.
5. Only if a new log is saved, import it into Splunk using a source name distinguishing it from the old `http_server.log` and validate an event at the new timestamp.
6. Add the new screenshots/log to the report as **newly performed follow-up evidence**. Do not relabel the original October 20 HTTP log as evidence of clicking from the HTML mock-up.

Limits: HTTP 200 alone cannot establish the click's source; correlation with the observed local action and timestamp supports a classroom sequence, not an actual T1566.002 intrusion.
