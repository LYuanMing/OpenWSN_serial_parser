import re


definitions={'components': {0: 'NULL', 1: 'OPENWSN', 2: 'IDMANAGER', 3: 'OPENQUEUE', 4: 'OPENSERIAL', 5: 'PACKETFUNCTIONS', 6: 'RANDOM', 7: 'RADIO', 8: 'IEEE802154', 9: 'IEEE802154E', 10: 'SIXTOP_TO_IEEE802154E', 11: 'IEEE802154E_TO_SIXTOP', 12: 'SIXTOP', 13: 'NEIGHBORS', 14: 'SCHEDULE', 15: 'SIXTOP_RES', 16: 'MSF', 17: 'OPENBRIDGE', 18: 'IPHC', 19: 'FRAG', 20: 'FORWARDING', 21: 'ICMPv6', 22: 'ICMPv6ECHO', 23: 'ICMPv6ROUTER', 24: 'ICMPv6RPL', 25: 'UDP', 26: 'SOCK_TO_UDP', 27: 'UDP_TO_SOCK', 28: 'OPENCOAP', 29: 'CJOIN', 30: 'OSCORE', 31: 'C6T', 32: 'CEXAMPLE', 33: 'CINFO', 34: 'CLEDS', 35: 'CSENSORS', 36: 'CSTORM', 37: 'CWELLKNOWN', 38: 'UECHO', 39: 'UINJECT', 40: 'RRT', 41: 'SECURITY', 42: 'USERIALBRIDGE', 43: 'UEXPIRATION', 44: 'UMONITOR', 45: 'CINFRARED'}, 'log_descriptions': {1: 'node joined', 2: 'sending CJOIN request', 3: 'OSCORE sequence number reached maximum value', 4: 'OSCORE replay protection failed', 5: 'OSCORE decryption and tag verification failed', 6: 'Aborted join process (code location {0})', 7: 'unknown transport protocol {0} (code location {1})', 8: 'unsupported port number {0} (code location {1})', 9: 'invalid checksum, expected 0x{:04x}, found 0x{:04x}', 10: 'received an echo request (length: {0})', 11: 'received an echo reply', 12: 'the received packet has expired', 13: 'packet expiry time reached, dropped', 14: 'unexpected DAO (code location {0}). A change maybe happened on dagroot node.', 15: 'unsupported ICMPv6 type {0} (code location {1})', 16: 'unsupported 6LoWPAN parameter {1} at location {0}, dropping packet', 17: 'no next hop for layer 3 destination {0:x}{1:x}', 18: 'invalid forward mode', 19: 'large DAGrank {0}, set to {1}', 20: 'packet discarded hop limit reached', 21: 'loop detected due to previous rank {0} lower than current node rank {1}', 22: 'upstream packet set to be downstream, possible loop.', 23: 'packet to forward is dropped (code location {0})', 25: 'invalid original packet size ({0} > {1})', 26: 'reassembled fragments into big packet (size: {0}, tag: {1})', 27: 'fast-forwarded all fragments with tag {0} (total size: {1})', 28: 'stored a fragment with offset {0} (currently in buffer: {1})', 29: 'reassembly or vrb timer expired for fragments with tag {0}', 30: 'fragmenting a big packet, original size {0}, number of fragments {1}', 31: 'bridge mismatch (code location {0})', 32: 'the slot {0} to be added is already in schedule', 33: 'neighbors table is full (max number of neighbor is {0})', 34: 'there is no sent packet in queue', 35: 'there is no received packet in queue', 36: 'schedule overflown', 37: 'sixtop return code {0} at sixtop state {1}', 38: 'sending a 6top request', 39: 'there are {0} cells to request mote', 40: 'the cells reserved to request mote contains slot {0} and slot {1}', 41: 'the received packet format is not supported (code location {0})', 42: 'the metadata type is not suppored', 43: 'TX cell usage during last period: {}', 44: 'RX cell usage during last period: {}', 45: 'wrong celltype {0} at slotOffset {1}', 46: 'unsupported IEEE802.15.4 parameter {1} at location {0}', 47: 'got desynchronized at slotOffset {0}', 48: 'synchronized at slotOffset {0}', 49: 'large timeCorr.: {0} ticks (code loc. {1})', 50: 'wrong state {0} in end of frame+sync', 51: 'wrong state {0} in startSlot, at slotOffset {1}', 52: 'wrong state {0} in timer fires, at slotOffset {1}', 53: 'wrong state {0} in start of frame, at slotOffset {1}', 54: 'wrong state {0} in end of frame, at slotOffset {1}', 55: 'maxTxDataPrepare overflows while at state {0} in slotOffset {1}', 56: 'maxRxAckPrepapare overflows while at state {0} in slotOffset {1}', 57: 'maxRxDataPrepapre overflows while at state {0} in slotOffset {1}', 58: 'maxTxAckPrepapre overflows while at state {0} in slotOffset {1}', 59: 'wdDataDuration overflows while at state {0} in slotOffset {1}', 60: 'wdRadio overflows while at state {0} in slotOffset {1}', 61: 'wdRadioTx overflows while at state {0} in slotOffset {1}', 62: 'wdAckDuration overflows while at state {0} in slotOffset {1}', 63: 'security error on frameType {0}, code location {1}', 64: 'invalid packet from radio', 65: 'getData asks for too few bytes, maxNumBytes={0}, fill level={1}', 66: 'wrong CRC in input Buffer', 67: 'buffer overflow detected (code location {0})', 68: 'busy sending', 69: "sendDone for packet I didn't send", 70: 'no free packet buffer (code location {0})', 71: 'no free timer or queue entry (code location {0})', 72: 'freeing unused memory', 73: 'freeing memory unsupported memory', 74: 'unknown message type {0}', 75: 'wrong address type {0} (code location {1})', 76: 'total packet size is too long, length {0} (adding {1} bytes)', 77: 'total packet size is too short, length {0} (removing {1} bytes)', 78: 'input length problem, length={0}', 79: 'booted', 80: 'maxretries reached (counter: {0})', 81: 'empty queue or trying to remove unknown timer id (code location {0})', 82: 'failed to push to lower layer', 83: 'received an invalid parameter', 84: 'copy packet content to small packet (pkt len {} < max len {})', 85: 'copy packet content to big packet (pkt len {} > max len {})'}, 'sixtop_returncodes': {0: 'RC_SUCCESS', 1: 'RC_EOL', 2: 'RC_ERROR', 3: 'RC_RESET', 4: 'RC_VER_ERR', 5: 'RC_SFID_ERR', 6: 'RC_SEQNUM_ERR', 7: 'RC_CELLLIST_ERR', 8: 'RC_BUSY', 9: 'RC_LOCKED'}, 'sixtop_states': {0: 'IDLE', 1: 'WAIT_ADDREQUEST_SENDDONE', 2: 'WAIT_DELETEREQUEST_SENDDONE', 3: 'WAIT_RELOCATEREQUEST_SENDDONE', 4: 'WAIT_COUNTREQUEST_SENDDONE', 5: 'WAIT_LISTREQUEST_SENDDONE', 6: 'WAIT_CLEARREQUEST_SENDDONE', 7: 'WAIT_ADDRESPONSE', 8: 'WAIT_DELETERESPONSE', 9: 'WAIT_RELOCATERESPONSE', 10: 'WAIT_COUNTRESPONSE', 11: 'WAIT_LISTRESPONSE', 12: 'WAIT_CLEARRESPONSE'}}


def extract_component_codes(fw_definitions_path):
    # find component codes in opendefs.h
    print("extracting firmware component names")

    codes_found = {}
    for line in open(fw_definitions_path, 'r'):
        m = re.search(' *COMPONENT_([^ .]*) *= *(.*), *', line)
        if m:
            name = m.group(1)
            try:
                code = int(m.group(2), 16)
            except ValueError:
                print("component '{}' - {} is not a hex number".format(name, m.group(2)))
            else:
                print("extracted component '{}' with code {}".format(name, code))
                codes_found[code] = name

    return codes_found


def extract_log_descriptions(fw_definitions_path):
    # find error codes in opendefs.h
    print("extracting firmware log descriptions.")

    codes_found = {}
    for line in open(fw_definitions_path, 'r'):
        m = re.search(' *ERR_.* *= *([xXA-Fa-f0-9]*), *// *(.*)', line)
        if m:
            desc = m.group(2).strip()
            try:
                code = int(m.group(1), 16)
            except ValueError:
                print("log description '{}' - {} is not a hex number".format(desc, m.group(2)))
            else:
                print("extracted log description '{}' with code {}".format(desc, code))
                codes_found[code] = desc

    return codes_found


def extract_6top_rcs(fw_6top_definitions_path):
    # find sixtop return codes in sixtop.h
    print("extracting 6top return codes.")

    codes_found = {}
    for line in open(fw_6top_definitions_path, 'r'):
        m = re.search(' *#define *IANA_6TOP_RC_([^ .]*) *([xXA-Za-z0-9]+) *// *([^ .]*).*', line)
        if m:
            name = m.group(3)
            try:
                code = int(m.group(2), 16)
            except ValueError:
                print("return code '{}': {} is not a hex number".format(name, m.group(2)))
            else:
                print("extracted 6top RC '{}' with code {}".format(name, code))
                codes_found[code] = name

    return codes_found


def extract_6top_states(fw_6top_definitions_path):
    # find sixtop state codes in sixtop.h
    print("extracting 6top states.")

    codes_found = {}
    for line in open(fw_6top_definitions_path, 'r'):
        m = re.search(' *SIX_STATE_([^ .]*) *= *([^ .]*), *', line)
        if m:
            name = m.group(1)
            try:
                code = int(m.group(2), 16)
            except ValueError:
                print("state '{}' - {} is not a hex number".format(name, m.group(2)))
            else:
                print("extracted 6top state '{}' with code {}".format(name, code))
                codes_found[code] = name

    return codes_found

