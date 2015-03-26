from serial import Serial
import time
import re
import struct
import logging
import sys
import collections


class Rf12Demo(Serial):
    SIG = "[RF12demo.12]"
    HEADER_FIELDS = ["hdr_is_dst", "hdr_dst_id", "hdr_src_id", "hdr_is_ack",
                     "hdr_wants_ack"]
    CONFIG_REGEX = re.compile(' [A-Z[\\]\^_] i(\d{1,2})\*? g(\d{1,3}) @ '
                              '(\d{1,3}) MHz ?(c1)? ?(o\d{1,4})? ?(q1)? ?(x\d)?')
    FORMATS = {
        0: 'decimal',
        1: 'hex',
        2: 'hex+ascii',
    }
    def __init__(self, payload_header, payload_body, collect=1, quiet=1,
                 format=1, *args, **kwargs):
        """
        Rf12demo dispays packet HDR byte and packet PAYLOAD, see here:
        http://jeelabs.org/2011/06/09/rf12-packet-format-and-design/
        It is assumed that payload has header and body and that the payload
        body format is defined by the first field of its header. Other than
        that, payload is arbitrary and can be defined with following arguments:

        @param payload_header - format of the first part of the packet payload.
            This part is common for any payload in the current protocol.

        @param payload_body - formats of the rest of the package payload used
            in the current protocol. Which format is used for given package
            is defined by the first field in the header, see example below.

        Format string doc:
                https://docs.python.org/2/library/struct.html#format-strings
            Note: this class asserts that little endian is always used.

        Field "src_id", if exists, is autopopulated with node id.
        Other field names are arbitrary, but following should not be used:
                "inf_type" and names in HEADER_FIELDS

        Example:
            payload_header = {
               "fields": ["type", "src_id"],
               "format": "<BB",
              }
            # field 'type' is the first field in header and its value defines
            # format of the of the package body and the key of payload_body
            # dictionary.
            payload_body = {
                0: {"name": "SetThr"},
                1: {"name": "GetAoA"},
                2: {
                    "name": "AoAresponse",
                    "fields": ["destination", "is_parent", "aoa"],
                    "format": "BBf",
                    },
                }
        @params collect, quiet and fomrat set initial values for those settings
            default values are 1 so node does not reply acks, does not log
            packages that are not passing crc and prints in hex format

        """
        super(Rf12Demo, self).__init__(*args, **kwargs)
        #assert little endian in all format strings
        payload_header["format"] = "<" + payload_header["format"].strip("@=<>!")
        for df in payload_body.values():
            df["format"] = "" if not df.get("format", False) else "<" + df["format"].strip("@=<>!")

        self.payload_header = payload_header
        self.payload_body = payload_body
        # helper attribute to search for payload_body key by name
        self.payload_types = dict(map(lambda (k, v): (v["name"], k),
                                      payload_body.items()))
        self.header_size = struct.calcsize(self.payload_header["format"])
        self.logger = logging.getLogger('rf12demo')
        self.logger.propagate = False
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            self.loghandler = logging.StreamHandler(sys.stdout)
            formatter = logging.Formatter('%(asctime)s.%(msecs)03d: %(message)s',
                                          datefmt='%H:%M:%S')
            self.loghandler.setFormatter(formatter)
            self.logger.addHandler(self.loghandler)

        self.reset()
        time.sleep(2)
        self.readline()  # empty line at the beginning
        assert self.read(len(self.SIG))==self.SIG,\
               "%s not found. Check if proper sketch is running." % self.SIG
        self.parse_config()
        time.sleep(1)
        self.flushIn()  #flush menu
        if self.collect!=collect:
            self.set_collect(collect)
        if self.quiet!=quiet:
            self.set_quiet(quiet)
        if self.format!=format:
            self.set_format(format)
        self.print_config()


    def reset(self):
        self.setDTR(False)
        time.sleep(0.022)
        self.setDTR(True)

    def set_config(self, command):
        self.write(command)
        self.parse_config()

    def parse_config(self):
        config = self.read(80)
        try:
            (nodeid, group, frequency, collect, offset, quiet, format) = \
                        re.search(self.CONFIG_REGEX, config).groups()
            assert int(nodeid) in range(32), 'Id'
            assert int(group) in range(253), 'Group'
            assert int(frequency) in (433, 868, 915), 'Frequency'
            assert collect in (None, 'c1'), 'Collect'
            assert offset is None or offset in range(96, 3904), 'Offset'
            assert quiet in (None, 'q1'), 'Quiet'
            assert format in (None, 'x1', 'x2'), 'Format'
        except AssertionError as e:
            raise Exception('%s assert error. Config string %s' % config, str(e))
        except Exception as e:
            raise Exception('%s Config string %s' % (config, str(e)))
        self.id = int(nodeid)
        self.group = int(group)
        self.frequency = int(frequency)
        self.collect = collect is not None
        self.offset = 1600 if offset is None else int(offset)
        self.quiet = quiet is not None
        self.format = 0 if format is None else int(format[1])

    def print_config(self):
        self.logger.info("       id: %d" % self.id)
        self.logger.info("    group: %d" % self.group)
        self.logger.info("frequency: %d MHz" % self.frequency)
        self.logger.info("  collect: %r" % self.collect)
        self.logger.info("   offset: %d" % self.offset)
        self.logger.info("    quiet: %r" % self.quiet)
        self.logger.info("   format: %s" % self.FORMATS[self.format])

    def set_id(self, nodeid):
        self.set_config('%di' % nodeid)
        assert self.id==id

    def set_group(self, group):
        self.set_config('%dg' % group)
        assert self.group==group

    def set_collect(self, collect):
        self.set_config('%dc' % collect)
        assert self.collect==bool(collect)

    def set_quiet(self, quiet):
        self.set_config('%dq' % quiet)
        assert self.quiet==bool(quiet)

    def set_format(self, format):
        self.set_config('%dx' % format)
        assert self.format==format

    def parse_received_information(self, line):
        """
        Incoming packets are reported as lines starting with "OK", "OKX",
        or "ASC" based on set format.
        Dataflash information is reported as lines starting with "DF".
        Packets with an invalid checksum or length are reported as lines
        starting with " ?" if enabled (see the "q" command).
        """
        self.logger.debug("parse_received_information, line: %s" % line)
        #TODO: add support for other information from node
        if self.FORMATS[self.format]=='hex':
            if line.startswith("OK"):
                data = {"inf_type": "package"}
                data.update(self.parse_received_packet(line.split()[1]))
                return data
        else:
            raise NotImplementedError("Format must be hex. Use set_format(1).")
        return {"inf_type": "unknown"}

    def log_received_information(self, timeout=0, log_package_function=None):
        """
        Log incomming information from jeelink. Currently only received
        packages are supported.
        """
        timer = time.time()+timeout
        while(time.time()<timer):
            line = self.readline()  # blocking read with self.timout
            if not line:
                continue
            timer = time.time()+timeout
            data = self.parse_received_information(line)
            if data["inf_type"]=="package":
                data.pop("inf_type")
                if log_package_function is not None:
                    log_package_function(self, data)
                else:
                    self.log_package(data)

    def log_package(self, data):
        # default package logging
        self.logger.info("Package header: ")
        for k in self.HEADER_FIELDS:
            self.logger.info(" %s: %s " % (k, str(data[k])))
        if not self.payload_header["fields"][0] in data:
            return
        self.logger.info("Payload header: ")
        for k in self.payload_header["fields"]:
            self.logger.info(" %s: %s " % (k, str(data[k])))
        body_fields = set(data) - set(self.HEADER_FIELDS) \
                    - set(self.payload_header["fields"])
        if body_fields:
            self.logger.info("Payload body: ")
            for k in body_fields:
                self.logger.info(" %s: %s " %(k, str(data[k])))

    def parse_package_header(self, hb):
        hdr = {}
        hdr["hdr_is_dst"] = bool(hb & 1<<6)
        hdr["hdr_src_id"] = None if hdr["hdr_is_dst"] else hb & 0x1F
        hdr["hdr_dst_id"] = None if not hdr["hdr_is_dst"] else hb & 0x1F
        hdr["hdr_is_ack"] = bool(hb & 1<<7)
        hdr["hdr_wants_ack"] = False if hdr["hdr_is_ack"] else bool(hb & 1<<5)
        return hdr

    def parse_received_packet(self, packet):
        """
        Parse packet string and extract data based on payload header which is
        first piece of data in payload.
        """
        self.logger.debug(packet)
        data = {}
        #TODO: add support for decimal package format
        if self.FORMATS[self.format]=='hex':
            # hdr
            hdr = struct.unpack("B", packet[:2].decode("hex"))[0]
            data.update(self.parse_package_header(hdr))
            if data["hdr_is_ack"]:
                return data
            packet = packet[2:]
            # header
            data.update(zip(self.payload_header.get("fields", []),
                            struct.unpack(self.payload_header["format"],
                                          packet[:self.header_size*2].decode("hex"))))
            packet = packet[self.header_size*2:]
            # body
            key = data[self.payload_header["fields"][0]]
            body_format = self.payload_body[key].get("format", [])
            body_fields = self.payload_body[key].get("fields", [])
            assert(len(body_format)==0 or len(body_format)-1==len(body_fields))
            data.update(zip(body_fields,
                        struct.unpack(body_format, packet.decode("hex"))))
        else:
            raise NotImplementedError("Format must be hex. Use set_format(1).")
        return data

    def send(self, destinations, *args, **kwargs):
        """ Send packets with data to single or multiple destinations. """
        # optional delay kwarg
        delay = kwargs.get("delay", 0.1)
        if not isinstance(destinations, collections.Iterable):
            destinations = [destinations]
        for destination in destinations:
            self.send_packet(destination, *args, **kwargs)
            time.sleep(delay)

    def send_packet(self, destination, name, data={}, ack=False):
        """
        Send data to destination node or 0 if broadcast. Data must include
        header except for first field and src_id and payload. Package payload
        defined by its name argument.

        """
        assert self.payload_header["format"][:2]=="<B",\
                "Only byte as header format is currently supported"
        # src_id is special and must be equal to this node id
        data["src_id"] = self.id
        # get payload type key from name
        pt_key = self.payload_types[name]
        # for this payload type pair fields with data for both header and body
        all_fields = self.payload_header["fields"][1:] + \
            self.payload_body[pt_key].get("fields", [])
        all_data = []
        for k in all_fields:
            try:
                all_data.append(data[k])
            except KeyError:
                self.logger.debug("Sending package with incomplete data. "
                                  "Missing fields are %s" % \
                                  ", ".join(all_fields[len(all_data):]))
                break  # breaks on first missing entry
        # insert pt_key as a first byte in payload header
        all_data.insert(0, pt_key)
        #remove little endian character < from formats
        all_formats = self.payload_header["format"][1:] + \
            self.payload_body[pt_key]["format"][1:]

        # parse all_data and prepare it for sending
        raw_data = []
        for dv, f in zip(all_data, all_formats):
            raw_data.extend(self._parse_for_sending(dv, f))
        assert len(raw_data)<=66, 'Maximum data size is 66 bytes'
        self.write(",".join(raw_data) + \
                   ",%d%s" % (destination, 'a' if ack else 's'))

    def _parse_for_sending(self, data_value, format):
        h = struct.pack("<"+format, data_value).encode("hex")
        return map(lambda x: str(int(x, 16)), map(''.join, zip(*[iter(h)]*2)))

    def flushIn(self):
        while (self.inWaiting()):
            self.read()
