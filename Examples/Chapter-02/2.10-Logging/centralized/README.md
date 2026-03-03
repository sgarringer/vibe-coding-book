# Centralized Logging — Setup Guides

Examples for Chapter 2.10.5 

## Why Centralized Logging

If an attacker compromises your server, the first thing they do is
delete or modify local logs. Centralized logging ships logs to a
separate system in real time, before they can be tampered with.

## Minimum Viable Setup (Section 2.10.5)

1. Ship logs to a central location (not just local files)
2. Retain logs for the periods in Table 2.19
3. Restrict log access (Section 2.10.7)
4. Set up at least one alert (Section 2.10.6)

## Platform Guides

| Platform                                     | Best For                 | Setup           |
| -------------------------------------------- | ------------------------ | --------------- |
| [AWS CloudWatch](./aws-cloudwatch/)             | AWS-hosted apps          | Low effort      |
| [Google Cloud Logging](./google-cloud-logging/) | GCP-hosted apps          | Low effort      |
| [Datadog](./datadog/)                           | Multi-cloud              | Low effort      |
| [Docker](./docker/)                             | Containerized apps       | Very low effort |
| [Fluentd/Fluent Bit](./fluentd/)                | Log shipping/aggregation | Medium effort   |
