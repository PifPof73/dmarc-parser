# dmarc-parser
A Python parser for DMARC reports that connects to IMAP and pushes metrics to graphite

During each processing a human readable log file is generated to summarize the activities.
On the graphite Server some dashboards could be configured to show the hits graphically.

## Configuration
The configuration is done in a config.ini file.
An example is added to this repository.

## Usage
dmarc-parser.py: parse a dmarc XML report
    <-f>        DMARC XML report file
    <-c>        configuration file (default: /etc/dmarc-parser/config.ini)
    <--imap>    Pull UNSEEN emails from IMAP server (as configured in config.ini)
    <-D>        debug mode (more verbose)
    <-h>        help
	
where --imap is my Default.