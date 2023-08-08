import enum

import chameleon_com
import chameleon_status

DATA_CMD_GET_APP_VERSION = 1000
DATA_CMD_CHANGE_MODE = 1001
DATA_CMD_GET_DEVICE_MODE = 1002
DATA_CMD_SET_SLOT_ACTIVATED = 1003
DATA_CMD_SET_SLOT_TAG_TYPE = 1004
DATA_CMD_SET_SLOT_DATA_DEFAULT = 1005
DATA_CMD_SET_SLOT_ENABLE = 1006

DATA_CMD_SET_SLOT_TAG_NICK = 1007
DATA_CMD_GET_SLOT_TAG_NICK = 1008

DATA_CMD_SLOT_DATA_CONFIG_SAVE = 1009

DATA_CMD_ENTER_BOOTLOADER = 1010
DATA_CMD_GET_DEVICE_CHIP_ID = 1011
DATA_CMD_GET_DEVICE_ADDRESS = 1012

DATA_CMD_SCAN_14A_TAG = 2000
DATA_CMD_MF1_SUPPORT_DETECT = 2001
DATA_CMD_MF1_NT_LEVEL_DETECT = 2002
DATA_CMD_MF1_DARKSIDE_DETECT = 2003
DATA_CMD_MF1_DARKSIDE_ACQUIRE = 2004
DATA_CMD_MF1_NT_DIST_DETECT = 2005
DATA_CMD_MF1_NESTED_ACQUIRE = 2006
DATA_CMD_MF1_CHECK_ONE_KEY_BLOCK = 2007
DATA_CMD_MF1_READ_ONE_BLOCK = 2008
DATA_CMD_MF1_WRITE_ONE_BLOCK = 2009

DATA_CMD_SCAN_EM410X_TAG = 3000
DATA_CMD_WRITE_EM410X_TO_T5577 = 3001

DATA_CMD_LOAD_MF1_BLOCK_DATA = 4000
DATA_CMD_SET_MF1_ANTI_COLLISION_RES = 4001

DATA_CMD_SET_EM410X_EMU_ID = 5000
DATA_CMD_SET_MF1_DETECTION_ENABLE = 5003
DATA_CMD_GET_MF1_DETECTION_COUNT = 5004
DATA_CMD_GET_MF1_DETECTION_RESULT = 5005


@enum.unique
class TagSenseType(enum.IntEnum):
    # 无场感应
    TAG_SENSE_NO = 0,
    # 低频125khz场感应
    TAG_SENSE_LF = 1,
    # 高频13.56mhz场感应
    TAG_SENSE_HF = 2,


@enum.unique
class TagSpecificType(enum.IntEnum):
    # Specific and required flags for non-existent types
    TAG_TYPE_UNKNOWN = 0
    # 125khz (ID card) series
    TAG_TYPE_EM410X = 1
    # Mifare series
    TAG_TYPE_MIFARE_Mini = 2
    TAG_TYPE_MIFARE_1024 = 3
    TAG_TYPE_MIFARE_2048 = 4
    TAG_TYPE_MIFARE_4096 = 5
    # NTAG series
    TAG_TYPE_NTAG_213 = 6
    TAG_TYPE_NTAG_215 = 7
    TAG_TYPE_NTAG_216 = 8

    @staticmethod
    def list(exclude_unknown=True):
        enum_list = list(map(int, TagSpecificType))
        if exclude_unknown:
            enum_list.remove(TagSpecificType.TAG_TYPE_UNKNOWN)
        return enum_list


class BaseChameleonCMD:
    """
        Chameleon cmd function
    """

    def __init__(self, chameleon: chameleon_com.ChameleonCom):
        """
        :param chameleon: chameleon instance, @see chameleon_device.Chameleon
        """
        self.device = chameleon

    def get_firmware_version(self) -> int:
        """
            Get firmware version number(application)
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_APP_VERSION, 0x00, None)
        return int.from_bytes(resp.data, 'little')
    
    def get_device_chip_id(self) -> str:
        """
            Get device chip id
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_CHIP_ID, 0x00, None)
        return resp.data.hex()
    
    def get_device_address(self) -> str:
        """
            Get device address
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_ADDRESS, 0x00, None)
        return resp.data[::-1].hex()
    

    def is_reader_device_mode(self) -> bool:
        """
            Get device mode, reader or tag
        :return: True is reader mode, else tag mode
        """
        resp = self.device.send_cmd_sync(DATA_CMD_GET_DEVICE_MODE, 0x00, None)
        return True if resp.data[0] == 1 else False

    def set_reader_device_mode(self, reader_mode: bool = True):
        """
            Change device mode, reader or tag
        :param reader_mode: True if reader mode, False if tag mode.
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_CHANGE_MODE, 0x00, 0x0001 if reader_mode else 0x0000)

    def scan_tag_14a(self):
        """
            14a tags in the scanning field
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_SCAN_14A_TAG, 0x00, None)

    def detect_mf1_support(self):
        """
            Detect whether it is a mifare classic tag
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_SUPPORT_DETECT, 0x00, None)

    def detect_mf1_nt_level(self):
        """
            Detect the level of nt vulnerabilities of mifare classic
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_NT_LEVEL_DETECT, 0x00, None)

    def detect_darkside_support(self):
        """
            Check if card is vulnerable to mifare classic darkside attack
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_MF1_DARKSIDE_DETECT, 0x00, None, timeout=20)

    def detect_nt_distance(self, block_known, type_known, key_known):
        """
            检测卡片的随机数距离
        :return:
        """
        data = bytearray()
        data.append(type_known)
        data.append(block_known)
        data.extend(key_known)
        return self.device.send_cmd_sync(DATA_CMD_MF1_NT_DIST_DETECT, 0x00, data)

    def acquire_nested(self, block_known, type_known, key_known, block_target, type_target):
        """
            Collect the key NT parameters needed for Nested decryption
        :return:
        """
        data = bytearray()
        data.append(type_known)
        data.append(block_known)
        data.extend(key_known)
        data.append(type_target)
        data.append(block_target)
        return self.device.send_cmd_sync(DATA_CMD_MF1_NESTED_ACQUIRE, 0x00, data)

    def acquire_darkside(self, block_target, type_target, first_recover: int or bool, sync_max):
        """
            Collect the key parameters needed for Darkside decryption
        :param block_target:
        :param type_target:
        :param first_recover:
        :param sync_max:
        :return:
        """
        data = bytearray()
        data.append(type_target)
        data.append(block_target)
        if isinstance(first_recover, bool):
            first_recover = 0x01 if first_recover else 0x00
        data.append(first_recover)
        data.append(sync_max)
        return self.device.send_cmd_sync(DATA_CMD_MF1_DARKSIDE_ACQUIRE, 0x00, data, timeout=sync_max + 5)

    def auth_mf1_key(self, block, type_value, key):
        """
            Verify the mf1 key, only verify the specified type of key for a single sector
        :param block:
        :param type_value:
        :param key:
        :return:
        """
        data = bytearray()
        data.append(type_value)
        data.append(block)
        data.extend(key)
        return self.device.send_cmd_sync(DATA_CMD_MF1_CHECK_ONE_KEY_BLOCK, 0x00, data)

    def read_mf1_block(self, block, type_value, key):
        """
            read mf1 monoblock
        :param block:
        :param type_value:
        :param key:
        :return:
        """
        data = bytearray()
        data.append(type_value)
        data.append(block)
        data.extend(key)
        return self.device.send_cmd_sync(DATA_CMD_MF1_READ_ONE_BLOCK, 0x00, data)

    def write_mf1_block(self, block, type_value, key, block_data):
        """
            Write mf1 single block
        :param block:
        :param type_value:
        :param key:
        :param block_data:
        :return:
        """
        data = bytearray()
        data.append(type_value)
        data.append(block)
        data.extend(key)
        data.extend(block_data)
        return self.device.send_cmd_sync(DATA_CMD_MF1_WRITE_ONE_BLOCK, 0x00, data)

    def read_em_410x(self):
        """
            Read the card number of EM410X
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_SCAN_EM410X_TAG, 0x00, None)

    def write_em_410x_to_t55xx(self, id_bytes: bytearray):
        """
            Write EM410X card number into T55XX
        :param id_bytes: ID card number
        :return:
        """
        new_key = [0x20, 0x20, 0x66, 0x66]
        old_keys = [
            [0x51, 0x24, 0x36, 0x48],
            [0x19, 0x92, 0x04, 0x27],
        ]
        if len(id_bytes) != 5:
            raise ValueError("The id bytes length must equal 5")
        data = bytearray()
        data.extend(id_bytes)
        data.extend(new_key)
        for key in old_keys:
            data.extend(key)
        return self.device.send_cmd_sync(DATA_CMD_WRITE_EM410X_TO_T5577, 0x00, data)

    def set_slot_activated(self, slot_index):
        """
            Set the currently active card slot
        :param slot_index: slot index, from 1 - 8 (not starting from 0 subscript)
        :return:
        """
        if slot_index < 1 or slot_index > 8:
            raise ValueError("The slot index range error(1-8)")
        data = bytearray()
        data.append(slot_index - 1)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_ACTIVATED, 0x00, data)

    def set_slot_tag_type(self, slot_index: int, tag_type: TagSpecificType):
        """
            Set the label type of the simulated card of the current card slot
            Note: This operation will not change the data in the flash, 
            and the change of the data in the flash will only be updated at the next save
        :param slot_index: Card slot number
        :param tag_type: label type
        :return:
        """
        if slot_index < 1 or slot_index > 8:
            raise ValueError("The slot index range error(1-8)")
        data = bytearray()
        data.append(slot_index - 1)
        data.append(tag_type)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_TAG_TYPE, 0x00, data)

    def set_slot_data_default(self, slot_index: int, tag_type: TagSpecificType):
        """
            Set the data of the simulated card in the specified card slot as the default data
            Note: This API will set the data in the flash together
        :param slot_index: Card slot number
        :param tag_type:The default label type to set
        :return:
        """
        if slot_index < 1 or slot_index > 8:
            raise ValueError("The slot index range error(1-8)")
        data = bytearray()
        data.append(slot_index - 1)
        data.append(tag_type)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_DATA_DEFAULT, 0x00, data)

    def set_slot_enable(self, slot_index: int, enable: bool):
        """
            Set whether the specified card slot is enabled
        :param slot_index: Card slot number
        :param enable: Whether to enable
        :return:
        """
        if slot_index < 1 or slot_index > 8:
            raise ValueError("The slot index range error(1-8)")
        data = bytearray()
        data.append(slot_index - 1)
        data.append(0x01 if enable else 0x00)
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_ENABLE, 0X00, data)

    def set_em140x_sim_id(self, id_bytes: bytearray):
        """
            Set the card number simulated by EM410x
        :param id_bytes: byte of the card number
        :return:
        """
        if len(id_bytes) != 5:
            raise ValueError("The id bytes length must equal 5")
        return self.device.send_cmd_sync(DATA_CMD_SET_EM410X_EMU_ID, 0x00, id_bytes)

    def set_mf1_detection_enable(self, enable: bool):
        """
            Set whether to enable the detection of the current card slot
        :param enable: Whether to enable
        :return:
        """
        data = bytearray()
        data.append(0x01 if enable else 0x00)
        return self.device.send_cmd_sync(DATA_CMD_SET_MF1_DETECTION_ENABLE, 0x00, data)

    def get_mf1_detection_count(self):
        """
            Get the statistics of the current detection records
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_GET_MF1_DETECTION_COUNT, 0x00, None)

    def get_mf1_detection_log(self, index: int):
        """
            Get detection logs from the specified index position
        :param index: start index
        :return:
        """
        data = bytearray()
        data.extend(index.to_bytes(4, "big", signed=False))
        return self.device.send_cmd_sync(DATA_CMD_GET_MF1_DETECTION_RESULT, 0x00, data)

    def set_mf1_block_data(self, block_start: int, block_data: bytearray):
        """
            Set the block data of the analog card of MF1
        :param block_start: Start setting the location of the block data，include this location
        :param block_data: Byte buffer of block data to be set, can contain multiple block data, automatically incremented from block_start
        :return:
        """
        data = bytearray()
        data.append(block_start & 0xFF)
        data.extend(block_data)
        return self.device.send_cmd_sync(DATA_CMD_LOAD_MF1_BLOCK_DATA, 0x00, data)

    def set_mf1_anti_collision_res(self, sak: bytearray, atqa: bytearray, uid: bytearray):
        """
            Set the anti-collision resource information of the MF1 analog card
        :param sak: sak bytes
        :param atqa: atqa array
        :param uid: card number array
        :return:
        """
        data = bytearray()
        data.extend(sak)
        data.extend(atqa)
        data.extend(uid)
        return self.device.send_cmd_sync(DATA_CMD_SET_MF1_ANTI_COLLISION_RES, 0X00, data)
    
    def set_slot_tag_nick_name(self, slot: int, sense_type: int, name: str):
        """
            Set the anti-collision resource information of the MF1 analog card
        :param slot: Card slot number
        :param sense_type: field type
        :param name: Card slot nickname
        :return:
        """
        data = bytearray()
        data.extend([slot, sense_type])
        data.extend(name.encode(encoding="gbk"))
        return self.device.send_cmd_sync(DATA_CMD_SET_SLOT_TAG_NICK, 0x00, data)
    
    def get_slot_tag_nick_name(self, slot: int, sense_type: int):
        """
            Set the anti-collision resource information of the MF1 analog card
        :param slot: Card slot number
        :param sense_type: field type
        :param name: Card slot nickname
        :return:
        """
        data = bytearray()
        data.extend([slot, sense_type])
        return self.device.send_cmd_sync(DATA_CMD_GET_SLOT_TAG_NICK, 0x00, data)
    
    def update_slot_data_config(self):
        """
            Update the configuration and data of the card slot to flash.
        :return:
        """
        return self.device.send_cmd_sync(DATA_CMD_SLOT_DATA_CONFIG_SAVE, 0x00, None)

    def enter_dfu_mode(self):
        """
            Reboot into DFU mode (bootloader)
        :return:
        """
        return self.device.send_cmd_auto(DATA_CMD_ENTER_BOOTLOADER, 0x00, close=True)


class NegativeResponseError(Exception):
    """
        Not positive response
    """


class PositiveChameleonCMD(BaseChameleonCMD):
    """
        The subclass rewrites the basic instruction interaction implementation class, 
        and performs separate encapsulation and result processing for each instruction
        If the result is successful, then the corresponding data is returned, 
        otherwise an exception is thrown directly
    """

    @staticmethod
    def check_status(status_ret, status_except):
        """
            Check status code, if accepted as successful
        :param status_ret: The status code returned after executing the command
        :param status_except: It can be considered as a successful status code
        :return:
        """
        if isinstance(status_except, int):
            status_except = [status_except]
        if status_ret not in status_except:
            if status_ret in chameleon_status.Device and status_ret in chameleon_status.message:
                raise NegativeResponseError(chameleon_status.message[status_ret])
            else:
                raise NegativeResponseError(f"Not positive response and unknown status {status_ret}")
        return

    def scan_tag_14a(self):
        ret = super(PositiveChameleonCMD, self).scan_tag_14a()
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def detect_nt_distance(self, block_known, type_known, key_known):
        ret = super(PositiveChameleonCMD, self).detect_nt_distance(block_known, type_known, key_known)
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def acquire_nested(self, block_known, type_known, key_known, block_target, type_target):
        ret = super(PositiveChameleonCMD, self).acquire_nested(
            block_known, type_known, key_known, block_target, type_target)
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def acquire_darkside(self, block_target, type_target, first_recover: int or bool, sync_max):
        ret = super(PositiveChameleonCMD, self).acquire_darkside(block_target, type_target, first_recover, sync_max)
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def auth_mf1_key(self, block, type_value, key):
        ret = super(PositiveChameleonCMD, self).auth_mf1_key(block, type_value, key)
        self.check_status(ret.status, [
            chameleon_status.Device.HF_TAG_OK,
            chameleon_status.Device.MF_ERRAUTH,
        ])
        return ret

    def read_mf1_block(self, block, type_value, key):
        ret = super(PositiveChameleonCMD, self).read_mf1_block(block, type_value, key)
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def write_mf1_block(self, block, type_value, key, block_data):
        ret = super(PositiveChameleonCMD, self).write_mf1_block(block, type_value, key, block_data)
        self.check_status(ret.status, chameleon_status.Device.HF_TAG_OK)
        return ret

    def read_em_410x(self):
        ret = super(PositiveChameleonCMD, self).read_em_410x()
        self.check_status(ret.status, chameleon_status.Device.LF_TAG_OK)
        return ret

    def write_em_410x_to_t55xx(self, id_bytes: bytearray):
        ret = super(PositiveChameleonCMD, self).write_em_410x_to_t55xx(id_bytes)
        self.check_status(ret.status, chameleon_status.Device.LF_TAG_OK)
        return ret

    def set_slot_activated(self, slot_index):
        ret = super(PositiveChameleonCMD, self).set_slot_activated(slot_index)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_slot_tag_type(self, slot_index: int, tag_type: TagSpecificType):
        ret = super(PositiveChameleonCMD, self).set_slot_tag_type(slot_index, tag_type)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_slot_data_default(self, slot_index: int, tag_type: TagSpecificType):
        ret = super(PositiveChameleonCMD, self).set_slot_data_default(slot_index, tag_type)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_slot_enable(self, slot_index: int, enable: bool):
        ret = super(PositiveChameleonCMD, self).set_slot_enable(slot_index, enable)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_em140x_sim_id(self, id_bytes: bytearray):
        ret = super(PositiveChameleonCMD, self).set_em140x_sim_id(id_bytes)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_mf1_detection_enable(self, enable: bool):
        ret = super(PositiveChameleonCMD, self).set_mf1_detection_enable(enable)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def get_mf1_detection_log(self, index: int):
        ret = super(PositiveChameleonCMD, self).get_mf1_detection_log(index)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_mf1_block_data(self, block_start: int, data: bytearray):
        ret = super(PositiveChameleonCMD, self).set_mf1_block_data(block_start, data)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret

    def set_mf1_anti_collision_res(self, sak: int, atqa: bytearray, uid: bytearray):
        ret = super(PositiveChameleonCMD, self).set_mf1_anti_collision_res(sak, atqa, uid)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret
    
    def set_slot_tag_nick_name(self, slot: int, sense_type: int, name: str):
        ret = super(PositiveChameleonCMD, self).set_slot_tag_nick_name(slot, sense_type, name)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret
    
    def get_slot_tag_nick_name(self, slot: int, sense_type: int):
        ret = super(PositiveChameleonCMD, self).get_slot_tag_nick_name(slot, sense_type)
        self.check_status(ret.status, chameleon_status.Device.STATUS_DEVICE_SUCCESS)
        return ret


if __name__ == '__main__':
    # connect to chameleon
    dev = chameleon_com.ChameleonCom()
    dev.open("com19")
    cml = BaseChameleonCMD(dev)
    ver = cml.get_firmware_version()
    print(f"Firmware number of application: {ver}")
    id = cml.get_device_chip_id()
    print(f"Device chip id: {id}")


    # disconnect
    dev.close()
    
    # nerver exit
    while True: pass
