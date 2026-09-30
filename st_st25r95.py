from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from enum import Enum

class ST25R95_DECODER_STATE(Enum):
    START = 0
    GET_CONTROL_BYTE = 1
    GET_POLL = 2
    GET_CMD = 3
    GET_RESP_CODE = 4
    GET_LEN = 5
    GET_DATA = 6
    GET_PROTOCOL = 7
    GET_REG = 8
    GET_IDLE_WU_SOURCE = 9
    GET_IDLE_ENTER_CTRL = 10
    GET_IDLE_WU_CTRL = 11
    GET_IDLE_LEAVE_CTRL = 12
    GET_IDLE_TIMING = 13
    GET_IDLE_DAC_DATA = 14
    GET_IDLE_PARAMS = 15
    GET_IDLE_RESP = 16
    
class ST25R95_TYPE(Enum):
    Send_Command = 0
    Reset = 1
    Read_Data = 2
    Poll = 3
    Unk = 4

COMMAND_CODE = {
    0x01: 'IDN',
    0x02: 'ProtocolSelect',
    0x03: 'PollField',
    0x04: 'SendRecv',
    0x05: 'Listen',
    0x06: 'Send',
    0x07: 'Idle',
    0x08: 'RdReg',
    0x09: 'WrReg',
    0x0B: 'SubFreqRes',
    0x0D: 'AC filter',
    0x55: 'Echo',
}

RESPONSE_CODE = {
    0x00: 'OK',
    0x55: 'Echo',
    0x63: 'EEmdSOFerror23',
    0x65: 'EEmdSOFerror10',
    0x66: 'ETr1 Too Big',
    0x67: 'ETr1 Too Small',
    0x68: 'EinternalError',
    0x82: 'EInvalidCmdLen',
    0x83: 'EInvalidProto',
    0x85: 'EUserStop',
    0x86: 'ECommError',
    0x87: 'EFrameWaitTOut',
    0x88: 'EInvalidSof',
    0x89: 'EBufOverflow',
    0x8A: 'EFramingError',
    0x8B: 'EEgtError',
    0x8C: 'EInvalidLen',
    0x8D: 'ECrcError',
    0x8E: 'ERecvLost',
    0x8F: 'ENoField',
}
# these response codes can contain 2 bits of data_len
RESPONSE_CODE_LEN = {
    0x80: 'EFrameRecvOK',
    0x90: 'EUnintByte',
}

PROTOCOL = {
    0x00: 'Field OFF',
    0x01: 'ISO/IEC 15693',
    0x02: 'ISO/IEC 14443-A',
    0x03: 'ISO/IEC 14443-B',
    0x04: 'FeliCa',
    0x12: 'ISO/IEC 14443-A CE',
}

REGISTER = {
    0x0A: 'Auto Detect Filter',
    0x3A: 'Timer Window',
    0x62: 'ACC_A or ARC_B',
    0x68: 'Analog Configuration',
    0x69: 'Wakeup Event',
}

AC_STATE = {
    0x00: 'Idle',
    0x01: 'Readya',
    0x04: 'Active',
    0x80: 'Halt',
    0x81: 'ReadyA*',
    0x84: 'Active*',
}

# Idle command constants
LFO_FREQ = {
    0b00: '32kHz',
    0b01: '16kHz',
    0b10: '8kHz',
    0b11: '4kHz'
}

# Control/Resume configuration bit descriptions
CTRL_RES_BITS = {
    'sleep_state': 0,
    'hibernate_state': 2,
    'vdda_enabled': 3,
    'hfo_enabled': 4,
    'lfo_enabled': 5,
    'dac_comp_high': 7,
    'iref_enabled': 8,
    'field_detector': 9
}

# Wake-up source bit descriptions
WU_SOURCE_BITS = {
    'timeout': 0,
    'tag_detection': 1,
    'field_detection': 2,
    'irq_in_low_pulse': 3,
    'ss_low_pulse': 4,
    'lfo_freq': 6  # 2 bits for frequency
}

def tx_flag(raw: int) -> str:
    flag = '('
    if raw & 0x80 == 0x80:
        flag += 'Topaz | '
    if raw & 0x40 == 0x40:
        flag += 'Split | '
    if raw & 0x20 == 0x20:
        flag += 'Append CRC | '
    if raw & 0x10 == 0x10:
        flag += 'Parity Framing mode | '
    flag += f"{raw&0xf} significant bits in last byte)"
    return flag

def rx_flag(raw: int) -> str:
    flag = '('
    if raw & 0x20 == 0x20:
        flag += 'CRC error | '
    if raw & 0x10 == 0x10:
        flag += 'Parity error | '
    flag += f"{raw&0xf} significant bits in last byte)"
    return flag

def ac_state(raw: int) -> str:
    state = ''
    if raw & 0x20 == 0x20:
        state += 'CRC error | '
    if raw & 0x10 == 0x10:
        state += 'Parity error | '
    state += f"{raw&0xf} significant bits in last byte)"
    return state

def parse_wake_up_source(byte_val: int) -> str:
    """Parse wake-up source configuration byte for Idle command"""
    lfo_bits = (byte_val >> 6) & 0b11
    lfo_freq = LFO_FREQ.get(lfo_bits, f'Unknown({lfo_bits})')
    sources = []
    if byte_val & (1 << 4):
        sources.append('SS_pulse')
    if byte_val & (1 << 3):
        sources.append('IRQ_IN')
    if byte_val & (1 << 2):
        sources.append('FieldDetect')
    if byte_val & (1 << 1):
        sources.append('TagDetect')
    if byte_val & 1:
        sources.append('Timeout')
    if not sources:
        sources.append('None')
    return f"LFO:{lfo_freq} WU_SRC:{'+'.join(sources)}"

def parse_ctrl_res_conf(byte_low: int, byte_high: int) -> str:
    """Parse control/resume configuration bytes for Idle command"""
    value = byte_low | (byte_high << 8)
    states = []
    if value & 1:
        states.append('Sleep')
    if value & (1 << 2):
        states.append('Hibernate')
    enabled = []
    if value & (1 << 3):
        enabled.append('VDDA')
    if value & (1 << 4):
        enabled.append('HFO')
    if value & (1 << 5):
        enabled.append('LFO')
    if value & (1 << 7):
        enabled.append('DAC_H')
    if value & (1 << 8):
        enabled.append('IREF')
    if value & (1 << 9):
        enabled.append('FieldDet')
    result = ''
    if states:
        result += f"Mode:{'+'.join(states)} "
    if enabled:
        result += f"En:{'+'.join(enabled)}"
    return result.strip()

def format_idle_params(params: dict) -> str:
    """Format all Idle command parameters into readable string"""
    parts = []
    if 'wakeup_source' in params:
        parts.append(params['wakeup_source'])
    if 'enter_ctrl' in params:
        parts.append(f"Enter:{params['enter_ctrl']}")
    if 'wu_ctrl' in params:
        parts.append(f"WU:{params['wu_ctrl']}")
    if 'leave_ctrl' in params:
        parts.append(f"Leave:{params['leave_ctrl']}")
    if 'timing' in params:
        timing = params['timing']
        parts.append(f"WUPeriod:{timing['period']} OSCstart:{timing['osc']} DACstart:{timing['dac']}")
    if 'dac_data' in params:
        dac = params['dac_data']
        parts.append(f"DACdata:{dac['low']:02X}/{dac['high']:02X}")
    if 'swing_count' in params and 'max_sleep' in params:
        parts.append(f"SwingsCnt:{params['swing_count']} MaxSleep:{params['max_sleep']}")
    return ' '.join(parts)

class Hla(HighLevelAnalyzer):
    
    def __init__(self):
        self.state = ST25R95_DECODER_STATE.START
        self.selected_protocol = 'Field OFF'
        self.last_command = ''
        
    def decode(self, frame: AnalyzerFrame):
        if frame.type == 'enable':
            self.state = ST25R95_DECODER_STATE.GET_CONTROL_BYTE
            self.begin_frame = frame.start_time
            self.data_len = 0
            self.data_cnt = 0
        elif frame.type == 'result':
            mosi = int.from_bytes(frame.data['mosi'], 'big')
            miso = int.from_bytes(frame.data['miso'], 'big')
            if self.state == ST25R95_DECODER_STATE.GET_CONTROL_BYTE:
                self.data = ''
                self.protocol = ''
                self.idle_params = {}
                self.idle_data_bytes = []
                self.flags = '{0:#0{1}x}'.format(miso, 4)
                self.send = True
                if mosi == 0x01:
                    self.type = ST25R95_TYPE.Reset
                elif mosi == 0x03:
                    self.type = ST25R95_TYPE.Poll
                    self.state = ST25R95_DECODER_STATE.GET_POLL
                elif mosi == 0x00:
                    self.type = ST25R95_TYPE.Send_Command
                    self.state = ST25R95_DECODER_STATE.GET_CMD
                elif mosi == 0x02:
                    self.type = ST25R95_TYPE.Read_Data
                    self.state = ST25R95_DECODER_STATE.GET_RESP_CODE
                    self.send = False
                else:
                    self.type = ST25R95_TYPE.Unk
            elif self.state == ST25R95_DECODER_STATE.GET_POLL:
                self.data += '{0:#0{1}x}'.format(miso, 4) + ' '
            elif self.state == ST25R95_DECODER_STATE.GET_CMD:
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.last_command = COMMAND_CODE.get(mosi, '?')
                self.cmd_resp = self.last_command
                self.state = ST25R95_DECODER_STATE.GET_LEN
            elif self.state == ST25R95_DECODER_STATE.GET_RESP_CODE:
                self.data += '{0:#0{1}x}'.format(miso, 4) + ' '
                self.cmd_resp = RESPONSE_CODE.get(miso, RESPONSE_CODE_LEN.get(miso & 0x9F, '?'))
                self.data_len = (miso & 0x60) << 3 if (self.cmd_resp == 'EFrameRecvOK' and self.cmd_resp == 'EUnintByte') else 0
                self.state = ST25R95_DECODER_STATE.GET_LEN
            elif self.state == ST25R95_DECODER_STATE.GET_LEN:
                self.data_len += mosi if self.send else miso
                self.data += '{0:#0{1}x}'.format(self.data_len, 4) + ' '
                if self.send:
                    if self.cmd_resp == 'WrReg' or self.cmd_resp == 'RdReg':
                        self.state = ST25R95_DECODER_STATE.GET_REG
                    elif self.cmd_resp == 'ProtocolSelect':
                        self.state = ST25R95_DECODER_STATE.GET_PROTOCOL
                    elif self.cmd_resp == 'Idle':
                        self.state = ST25R95_DECODER_STATE.GET_IDLE_WU_SOURCE
                    else:
                        self.state = ST25R95_DECODER_STATE.GET_DATA
                else:
                    if self.last_command == 'Idle':
                        self.state = ST25R95_DECODER_STATE.GET_IDLE_RESP
                    else:
                        self.state = ST25R95_DECODER_STATE.GET_DATA
            elif self.state == ST25R95_DECODER_STATE.GET_PROTOCOL:
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                self.selected_protocol = PROTOCOL.get(mosi, '?')
                self.cmd_resp += '(' + self.selected_protocol + ')'
                self.state = ST25R95_DECODER_STATE.GET_DATA
            elif self.state == ST25R95_DECODER_STATE.GET_REG:
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                self.cmd_resp += '(' + REGISTER.get(mosi, '?') + ')'
                self.state = ST25R95_DECODER_STATE.GET_DATA
            elif self.state == ST25R95_DECODER_STATE.GET_DATA:
                self.data += '{0:#0{1}x}'.format(mosi if self.send else miso, 4) + ' '
                self.data_cnt += 1
                if self.last_command == 'PollField':
                    self.cmd_resp += ' (No RF field detected)' if self.data_len == 0 or miso == 0 else ' (RF field detected)'
                elif self.last_command == 'AC filter':
                    if self.data_len == 2 and self.data_cnt == 1:
                        self.cmd_resp += ' (Get AC State)'
                    elif self.data_len == 1:
                        if self.send:
                            self.cmd_resp += ' (Set AC State: ' + AC_STATE.get(mosi, '?') + ')'
                        else:
                            self.cmd_resp += ' (AC State: ' + AC_STATE.get(miso, '?') + ')'
                    elif self.data_len == 0:
                        self.cmd_resp += ' (Disable AC Filter)'
                elif (self.last_command == 'Listen' or self.last_command == 'SendRecv') and (self.cmd_resp == 'EFrameRecvOK' or self.cmd_resp == 'EUnintByte' or self.cmd_resp == 'EFrameWaitTOut'):
                    if ((self.data_len == self.data_cnt + 2 and self.selected_protocol == 'ISO/IEC 14443-A') or (self.data_len == self.data_cnt and self.selected_protocol == 'ISO/IEC 14443-A CE')) and (self.cmd_resp == 'EFrameRecvOK' or self.cmd_resp == 'EUnintByte'):
                        self.protocol += rx_flag(miso)
                    else:
                        self.protocol += '{0:#0{1}x}'.format(miso, 4) + ' '
                elif self.last_command == 'Send' or self.last_command == 'SendRecv':
                    if self.data_len == self.data_cnt and (self.selected_protocol == 'ISO/IEC 14443-A' or self.selected_protocol == 'ISO/IEC 14443-A CE'):
                        self.protocol += tx_flag(mosi)
                    else:
                        self.protocol += '{0:#0{1}x}'.format(mosi, 4) + ' '
            # Idle command parameter parsing states
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_WU_SOURCE:
                self.idle_data_bytes.append(mosi)
                self.idle_params['wakeup_source'] = parse_wake_up_source(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                self.state = ST25R95_DECODER_STATE.GET_IDLE_ENTER_CTRL
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_ENTER_CTRL:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 3:  # After 2 bytes of enter_ctrl
                    self.idle_params['enter_ctrl'] = parse_ctrl_res_conf(self.idle_data_bytes[1], self.idle_data_bytes[2])
                    self.state = ST25R95_DECODER_STATE.GET_IDLE_WU_CTRL
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_WU_CTRL:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 5:  # After 2 bytes of wu_ctrl
                    self.idle_params['wu_ctrl'] = parse_ctrl_res_conf(self.idle_data_bytes[3], self.idle_data_bytes[4])
                    self.state = ST25R95_DECODER_STATE.GET_IDLE_LEAVE_CTRL
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_LEAVE_CTRL:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 7:  # After 2 bytes of leave_ctrl
                    self.idle_params['leave_ctrl'] = parse_ctrl_res_conf(self.idle_data_bytes[5], self.idle_data_bytes[6])
                    self.state = ST25R95_DECODER_STATE.GET_IDLE_TIMING
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_TIMING:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 10:  # After timing bytes (wu_period, osc_start, dac_start)
                    self.idle_params['timing'] = {
                        'period': self.idle_data_bytes[7],
                        'osc': self.idle_data_bytes[8],
                        'dac': self.idle_data_bytes[9]
                    }
                    self.state = ST25R95_DECODER_STATE.GET_IDLE_DAC_DATA
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_DAC_DATA:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 12:  # After DAC data bytes
                    self.idle_params['dac_data'] = {
                        'low': self.idle_data_bytes[10],
                        'high': self.idle_data_bytes[11]
                    }
                    self.state = ST25R95_DECODER_STATE.GET_IDLE_PARAMS
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_PARAMS:
                self.idle_data_bytes.append(mosi)
                self.data += '{0:#0{1}x}'.format(mosi, 4) + ' '
                self.data_cnt += 1
                if self.data_cnt == 14:  # After swing_count and max_sleep
                    self.idle_params['swing_count'] = self.idle_data_bytes[12]
                    self.idle_params['max_sleep'] = self.idle_data_bytes[13]
                    # Format the complete Idle command description
                    self.cmd_resp = 'Idle (' + format_idle_params(self.idle_params) + ')'
                    self.state = ST25R95_DECODER_STATE.GET_DATA
            elif self.state == ST25R95_DECODER_STATE.GET_IDLE_RESP:
                self.data += '{0:#0{1}x}'.format(miso, 4) + ' '
                self.data_cnt += 1
                self.cmd_resp += ' (' + parse_wake_up_source(miso) + ')'
                self.state = ST25R95_DECODER_STATE.GET_DATA
        elif frame.type == 'disable':
            self.state = ST25R95_DECODER_STATE.START
            bugs = ''
            if self.data_len > self.data_cnt and self.last_command != 'Echo':
                bugs += '[frame aborted, missing data] '
            if self.selected_protocol == 'ISO/IEC 14443-B' and self.data_len > 528:
                bugs += '[Max data_len of 528 bytes exceded] '
            if self.selected_protocol == 'ISO/IEC 14443-A' and self.data_len > 256:
                bugs += '[Max data_len of 256 bytes exceded] '
            if (self.type == ST25R95_TYPE.Send_Command) or (self.type == ST25R95_TYPE.Read_Data):
                return AnalyzerFrame(self.type.name, self.begin_frame, frame.end_time, {
                    'cmd/resp': self.cmd_resp,
                    'len': f'{self.data_len}',
                    'data': self.data,
                    'protocol': self.protocol,
                    'flags': self.flags,
                    'bugs': bugs
                }) 
            else:
                return AnalyzerFrame(self.type.name, self.begin_frame, frame.end_time, {
                    'data': self.data,                                                                      
                    'flags': self.flags
                })  
