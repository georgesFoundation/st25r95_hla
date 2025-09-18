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
                self.state = ST25R95_DECODER_STATE.GET_REG if (self.cmd_resp == 'WrReg' or self.cmd_resp == 'RdReg') else ST25R95_DECODER_STATE.GET_PROTOCOL if self.cmd_resp == 'ProtocolSelect' else ST25R95_DECODER_STATE.GET_DATA
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
                elif (self.last_command == 'Listen' or self.last_command == 'SendRecv') and self.cmd_resp == 'EFrameRecvOK':
                    if self.data_len == self.data_cnt and (self.selected_protocol == 'ISO/IEC 14443-A' or self.selected_protocol == 'ISO/IEC 14443-A CE'):
                        self.protocol += rx_flag(miso)                                                                                                  
                    else:
                        self.protocol += '{0:#0{1}x}'.format(miso, 4) + ' '
                elif self.last_command == 'Send' or self.last_command == 'SendRecv':
                    if self.data_len == self.data_cnt and (self.selected_protocol == 'ISO/IEC 14443-A' or self.selected_protocol == 'ISO/IEC 14443-A CE'):
                        self.protocol += tx_flag(mosi)
                    else:
                        self.protocol += '{0:#0{1}x}'.format(mosi, 4) + ' '
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
