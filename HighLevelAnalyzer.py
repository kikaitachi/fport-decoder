# High Level Analyzer
# For more information and documentation, please go to https://support.saleae.com/extensions/high-level-analyzer-extensions

from saleae.analyzers import HighLevelAnalyzer, AnalyzerFrame, StringSetting, NumberSetting, ChoicesSetting
from saleae.data.timing import GraphTimeDelta
from enum import Enum


class State(Enum):
    WAIT_FOR_FIRST_BYTE = 1
    WAIT_FOR_DOWNLINK_LEN = 2
    WAIT_FOR_DOWNLINK_TYPE = 3
    READ_DATA = 4
    WAIT_FOR_UPLINK_TYPE = 5
    WAIT_FOR_UPLINK_DATA = 6

class FrameType(Enum):
    UNKNOWN = 0
    CONTROL = 1
    DOWNLINK_DATA = 2
    UPLINK_DATA = 3

# High level analyzers must subclass the HighLevelAnalyzer class.
class Hla(HighLevelAnalyzer):
    result_types = {
        'decoded_data': {
            'format': '{{data.decoded}}'
        }
    }

    def __init__(self):
        '''
        Initialize HLA.
        '''

        self.state = State.WAIT_FOR_FIRST_BYTE

    def decode(self, frame: AnalyzerFrame):
        '''
        Process a frame from the input analyzer, and optionally return a single `AnalyzerFrame` or a list of `AnalyzerFrame`s.
        '''

        data = frame.data['data']
        if self.state == State.WAIT_FOR_FIRST_BYTE:
            if data == bytes.fromhex('7E'):
                self.state = State.WAIT_FOR_DOWNLINK_LEN
                self.header_start_time = frame.start_time
            elif data == bytes.fromhex('08'):
                self.state = State.WAIT_FOR_UPLINK_TYPE
                self.header_start_time = frame.start_time
        elif self.state == State.WAIT_FOR_DOWNLINK_LEN:
            self.state = State.WAIT_FOR_DOWNLINK_TYPE
            self.data_len = data[0] + 1
            self.frame_data = []
            if self.data_len < 13:  # Can't be valid frame
                self.state = State.WAIT_FOR_FIRST_BYTE
        elif self.state == State.WAIT_FOR_DOWNLINK_TYPE:
            self.state = State.READ_DATA
            if data == bytes.fromhex('00'):
                decoded = 'Control start'
                self.frame_type = FrameType.CONTROL
            elif data == bytes.fromhex('01'):
                decoded = 'Downlink start'
                self.frame_type = FrameType.DOWNLINK_DATA
            else:
                decoded = 'Unknown frame'
                self.frame_type = FrameType.UNKNOWN
            return AnalyzerFrame('decoded_data', self.header_start_time, frame.end_time, {
                'decoded': decoded
            })
        elif self.state == State.READ_DATA:
            self.frame_data.append({
                'byte': data[0],
                'start_time': frame.start_time,
                'end_time': frame.end_time
            })
            if len(self.frame_data) == self.data_len:
                self.state = State.WAIT_FOR_FIRST_BYTE
                channels = self.data_len * 8 // 11  # 11 bits / channel
                frames = []
                if (self.frame_type == FrameType.CONTROL):
                    start_time = self.frame_data[0]['start_time']
                    bit_duration = float(self.frame_data[0]['end_time'] - start_time) / 10
                    value = 0
                    bits = 0
                    channel = 0
                    for f in self.frame_data:
                        value |= f['byte'] << bits
                        bits += 8
                        if bits >= 11:
                            channel += 1
                            end_time = start_time + GraphTimeDelta(bit_duration * 11)
                            frames.append(AnalyzerFrame('decoded_data',
                                                        start_time,
                                                        end_time,
                                                        { 'decoded': 'ch' + str(channel) + ':' + str(value >> (bits - 11)) }))
                            value & (0xFFFF << (bits - 11))
                            bits -= 11
                            start_time = end_time
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-4]['start_time'],
                                                self.frame_data[-4]['end_time'],
                                                { 'decoded': 'Flags' }))
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-3]['start_time'],
                                                self.frame_data[-3]['end_time'],
                                                { 'decoded': 'RSSI' }))
                frames.append(AnalyzerFrame('decoded_data',
                                            self.frame_data[-2]['start_time'],
                                            self.frame_data[-2]['end_time'],
                                            { 'decoded': 'CRC' }))
                frames.append(AnalyzerFrame('decoded_data',
                                            frame.start_time,
                                            frame.end_time,
                                            { 'decoded': 'End' }))
                return frames
