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
                return AnalyzerFrame('decoded_data',
                                     frame.start_time,
                                     frame.end_time,
                                     { 'decoded': 'Head' })
            elif data == bytes.fromhex('08'):
                self.state = State.WAIT_FOR_UPLINK_TYPE
        elif self.state == State.WAIT_FOR_DOWNLINK_LEN:
            self.state = State.WAIT_FOR_DOWNLINK_TYPE
            self.data_len = data[0] + 1
            self.frame_data = []
            if self.data_len < 9:  # Can't be valid frame
                self.state = State.WAIT_FOR_FIRST_BYTE
            return AnalyzerFrame('decoded_data',
                                 frame.start_time,
                                 frame.end_time,
                                 { 'decoded': 'Len:' + str(data[0]) })
        elif self.state == State.WAIT_FOR_DOWNLINK_TYPE:
            self.state = State.READ_DATA
            if data == bytes.fromhex('00'):
                self.frame_type = FrameType.CONTROL
                return AnalyzerFrame('decoded_data',
                                     frame.start_time,
                                     frame.end_time,
                                     { 'decoded': 'Type:control' })
            elif data == bytes.fromhex('01'):
                self.frame_type = FrameType.DOWNLINK_DATA
                return AnalyzerFrame('decoded_data',
                                     frame.start_time,
                                     frame.end_time,
                                     { 'decoded': 'Type:downlink' })
            else:
                self.frame_type = FrameType.UNKNOWN
                return AnalyzerFrame('decoded_data',
                                     frame.start_time,
                                     frame.end_time,
                                     { 'decoded': 'Type:unknown' })
        elif self.state == State.READ_DATA:
            self.frame_data.append({
                'byte': data[0],
                'start_time': frame.start_time,
                'end_time': frame.end_time
            })
            if len(self.frame_data) == self.data_len:
                self.state = State.WAIT_FOR_FIRST_BYTE
                channels = (self.data_len - 3) * 8 // 11  # 11 bits / channel
                bit_duration = 0.000008681  # 115200 bps
                frames = []
                if (self.frame_type == FrameType.CONTROL):
                    start_time = self.frame_data[0]['start_time'] + GraphTimeDelta(bit_duration)
                    value = 0
                    bits = 0
                    channel = 0
                    for f in self.frame_data:
                        value |= f['byte'] << bits
                        bits += 8
                        if bits >= 11:
                            channel += 1
                            end_time = f['end_time'] - GraphTimeDelta(bit_duration * (bits - 10.5))
                            frames.append(AnalyzerFrame('decoded_data',
                                                        start_time,
                                                        end_time,
                                                        { 'decoded': 'ch' + str(channel) + ':' + str(value & 0x07FF) }))
                            if channel == channels:
                                break
                            value >>= 11
                            bits -= 11
                            start_time = end_time
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 4.5),
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 3.5),
                                                { 'decoded': 'failsafe:' + str(self.frame_data[-4]['byte'] & 0x08 > 0).lower() }))
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 3.5),
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 2.5),
                                                { 'decoded': 'lost frame:' + str(self.frame_data[-4]['byte'] & 0x04 > 0).lower() }))
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 2.5),
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 1.5),
                                                { 'decoded': 'ch18:' + str(self.frame_data[-4]['byte'] & 0x02 > 0).lower() }))
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 1.5),
                                                self.frame_data[-4]['end_time'] - GraphTimeDelta(bit_duration * 0.5),
                                                { 'decoded': 'ch17:' + str(self.frame_data[-4]['byte'] & 0x01 > 0).lower() }))
                    frames.append(AnalyzerFrame('decoded_data',
                                                self.frame_data[-3]['start_time'],
                                                self.frame_data[-3]['end_time'],
                                                { 'decoded': 'RSSI:' + str(self.frame_data[-3]['byte']) }))
                frames.append(AnalyzerFrame('decoded_data',
                                            self.frame_data[-2]['start_time'],
                                            self.frame_data[-2]['end_time'],
                                            { 'decoded': 'CRC:' + str(self.frame_data[-2]['byte']) }))
                frames.append(AnalyzerFrame('decoded_data',
                                            frame.start_time,
                                            frame.end_time,
                                            { 'decoded': 'End' }))
                return frames
