Simple API for serial communication with JeeNode running `rf12_demo.ino` sketch.

rf12_demo.ino documentation: http://jeelabs.net/projects/jeelib/wiki/RF12demo


## Requirements:

 * pyserial: pip install pyserial


## Example usage:

Define custom payload header and body:

```
payload_header = {
               "fields": ["type", "src_id"],
               "format": "BB",
              }
payload_body = {
                0: {"name": "Reset"},
                1: {"name": "SetThr"},
                2: {"name": "GetAoA"},
                3: {
                    "name": "AoAresponse",
                    "fields": ["destination", "is_parent", "aoa"],
                    "format": "BBf",
                    },
                4: {
                    "name": "Token",
                    "fields": ["donep1",],
                    "format": "B",
                    },
                5: {"name": "DoIniLoc"},
                6: {"name": "StartStitch"},
                7: {
                    "name": "LetUsStitch",
                    "fields": map(lambda x: str(x), range(16)),
                    "format": "BHH"*16,
                    },
                }
```

Create jeelink object for JeeLink node running `rf12demo.ino` sketch on port COM24.

```
jeelink = Rf12Demo(payload_body, payload_header, port='COM24',
                   baudrate=57600, timeout=3)
```

Sending Token package to node 2 with "donep1" set to 180

```
jeelink.send([2, "Token", {"donep1": 180})
jeelink.log_received_information(timeout=10)
```

Change the format of the log messages:

```
import logging
jeelink.loghandler.setFormatter(logging.Formatter('%(msecs)03d: %(message)s'))
```

Add new log handler i.e. for logging into file

```
fileHandler = logging.handlers.RotatingFileHandler('rf12demo.log')
fileHandler.setFormatter(jeelink.loghandler.formatter)
jeelink.logger.addHandler(fileHandler)
```

Define custom log package function based on protocol data

example log: `17:44:05.553: AoAresponse [2 -> all]: 1, 0, 34.7697067261`

```
def log_package_example(jeelink, data):
    name = jeelink.payload_body[data["type"]]["name"]
    src = str(data["src_id"])
    dst = "all" if data["hdr_dst_id"] is None else str(data["hdr_dst_id"])
    payload_body = ", ".join([str(data[k]) for k in jeelink.payload_body[data["type"]].get("fields", [])])
    payload_body = ": " + payload_body if payload_body else ""
    log = "%s [%s -> %s]%s" % (name, src, dst, payload_body)
    jeelink.logger.info(log)
```

This function can be passed as argument to log_received_information:

```
jeelink.log_received_information(10, log_package_example)
```
