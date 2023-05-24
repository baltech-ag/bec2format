HWCID_MAP = dict(
    UC_AT90MEGA128=0x01,
    UC_AT90USB128X=0x04,
    UC_AT90MEGA256X=0x07,
    UC_ATXMEGA_A=0x08,
    UC_ATXMEGA_A_SMALL=0x09,
    UC_ATXMEGA_C=0x0A,
    UC_MK22FN512XXX12=0x0B,
    UC_MK64FX512XXX12=0x0C,
    UC_MK65FN2M0XXX18=0x0D,
    UC_STM32U585=0x0E,
    UC_STM32U575=0x0F,
    CLOCK_13MHZ=0x20,
    CLOCK_8MHZ=0x21,
    CLOCK_16MHZ=0x22,
    CLOCK_27MHZ=0x23,
    CLOCK_INTERN=0x24,
    PINALLOC_PROTOTYPE=0x31,
    PINALLOC_IDENGINE_X=0x32,
    PINALLOC_SHARKM=0x33,
    PINALLOC_SHARKE=0x34,
    PINALLOC_CCT200=0x35,
    SRAM_1KB=0x66,
    SRAM_2KB=0x67,
    SRAM_4KB=0x68,
    SRAM_8KB=0x69,
    SRAM_16KB=0x6A,
    SRAM_32KB=0x6B,
    SRAM_64KB=0x6C,
    SRAM_128KB=0x6D,
    SRAM_256KB=0x6E,
    FLASH_1KB=0x76,
    FLASH_2KB=0x77,
    FLASH_4KB=0x78,
    FLASH_8KB=0x79,
    FLASH_16KB=0x7A,
    FLASH_32KB=0x7B,
    FLASH_64KB=0x7C,
    FLASH_128KB=0x7D,
    FLASH_256KB=0x7E,
    FLASH_512KB=0x7F,
    EEPROM_16BYTE=0x86,
    EEPROM_32BYTE=0x87,
    EEPROM_64BYTE=0x88,
    EEPROM_128BYTE=0x89,
    EEPROM_256BYTE=0x8A,
    EEPROM_512BYTE=0x8B,
    EEPROM_1KB=0x8C,
    EEPROM_2KB=0x8D,
    EEPROM_4KB=0x8E,
    PN512=0x93,
    RC632=0x94,
    SM05=0x95,
    SC2560=0x96,
    ROIN=0x97,
    TDA8007=0x98,
    EM4095=0x99,
    PNXXX_2=0x9A,
    SM4200=0x9B,
    RC663=0x9C,
    SL811=0x9D,
    CP220X=0x9E,
    HTRC110=0x9F,
    CCUART=0xA0,
    DM9006=0xA1,
    PG12864_ROTATED=0xA2,
    PG12864=0xA3,
    AT45DBXXXX=0xA4,
    TEST_DUMMY=0xA5,
    TEST_DUMMY2=0xA6,
    EXT_SRAM=0xA7,
    BEEPER_PWM=0xA8,
    BEEPER=0xA9,
    GREEN_LED=0xAA,
    RED_LED=0xAB,
    RELAY=0xAC,
    PN5180=0xAD,
    MEDUSA_QKEY=0xAF,
    HIDSE3100=0xB0,
    PCA9634=0xB1,
    ODINW262=0xB2,
    BLUE_LED=0xB3,
    APP_PROCESSOR_XMEGA256_A3U=0xB4,
    MK125=0xB5,
    BGM12X_DETUNED=0xB6,
    USB=0xB7,
    ETH1=0xB8,
    ETH2=0xB9,
    AD7147=0xBA,
    REED_SWITCH=0xBB,
    VCNL4010=0xBC,
    SM4500=0xBD,
    BGM12X=0xBE,
    BGM220=0xBF,
)

REV_HWCID_MAP = {v: k for k, v in HWCID_MAP.items()}