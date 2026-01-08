# edl-aggregator
Used to aggregate lists of IP addresses by cloud provider or ASN. This utilizes RADb or fails over to RIPE Stat API to lookup ASNs for their IP ranges. If ran standalone, the ip list is hosted and will refresh by default every 60 minutes. Please look through the config.json for the various options. The high_risk_asns are configured to be at the top of the list, in case systems truncate large lists.

# To create an executable:

```
go get edl-aggregator
# For the file output for the executable, it depends on what OS you are building on. The following is for a Windows OS and exe to run
go build -o edl-aggregator.exe
```

# To run and configure

```
# No argument will run the executable indefinitely and create a new config.json file if none exists. Accessing web interface should be via http://localhost:8080/admin and the list will be hosted at http://localhost:8080/edl
edl-aggregator.exe

# Only allowed arguments are -h (help and -output) Output will only run the tool once and generate a file with the list of IP addresses.
edl-aggregator.exe -output ip-list.txt
```

# Default config file

```
{
  "server_port": ":8080",
  "refresh_interval_minutes": 60,
  "max_lines": 100000,
  "admin_user": "admin",
  "admin_pass": "changeme",
  "sources": {
    "include_ipv6": false,
    "include_aws": true,
    "include_azure": true,
    "include_gcp": true,
    "include_oracle": true,
    "include_linode": true,
    "high_risk_asns": [
      "200373"
    ],
    "generic_asns": [
      "212238",
      "9009",
      "60068",
      "52393"
    ]
  },
  "whitelist": {
    "_comment": "STRATEGY TIP: Whitelisting a /32 (Precise) inside a large block creates many fragments. Whitelisting a /24 (Buffer) creates fewer fragments.",
    "asns": [
      "15169"
    ],
    "cidrs": [
      "1.2.3.4/32"
    ]
  }
}
```

# Modify configs via web interface

- visit http://localhost:8080/admin (or configured port, if the config.json is changed)
- Log in with credentials (from config.json)
- Modify the Configuration (JSON) right from the web interface and hit Save & Refresh List.
- Logs of tool output can also be viewed from the View Logs button.
