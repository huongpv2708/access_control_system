#ifndef RC522_API_MODULE_H
#define RC522_API_MODULE_H

#define MFRC522_VERSION_BASE 0x90
#define MFRC522_VERSION_1 0x91
#define MFRC522_VERSION_2 0x92

#define NR_KNOWN_KEYS 8

#define DEF_FIFO_LENGTH 64 /* FIFO size = 64byte */
#define RC522_MAX_LEN 16   /* The maximum length of data received */

// MF522command word
#define PCD_Idle				0x00		// no action, cancels current command execution
#define PCD_Mem					0x01		// stores 25 bytes into the internal buffer
#define PCD_GenerateRandomID	0x02		// generates a 10-byte random ID number
#define PCD_CalcCRC				0x03		// activates the CRC coprocessor or performs a self-test
#define PCD_Transmit			0x04		// transmits data from the FIFO buffer
#define PCD_NoCmdChange			0x07		// no command change, can be used to modify the CommandReg register bits without affecting the command, for example, the PowerDown bit
#define PCD_Receive				0x08		// activates the receiver circuits
#define PCD_Transceive 			0x0C		// transmits data from FIFO buffer to antenna and automatically activates the receiver after transmission
#define PCD_MFAuthent 			0x0E		// performs the MIFARE standard authentication as a reader
#define PCD_SoftReset			0x0F		// resets the MFRC522

// Mifare_One Card command word
#define PICC_REQIDL             0x26        // line-tracking area is dormant
#define PICC_REQALL             0x52        // line-tracking area is interfered
#define PICC_ANTICOLL           0x93        // Anti collision
#define PICC_SElECTTAG          0x93        // choose cards
#define PICC_AUTHENT1A          0x60        // Verify A key
#define PICC_AUTHENT1B          0x61        // Verify B key
#define PICC_READ               0x30        // Reader Module
#define PICC_WRITE              0xA0        // letter block

#define PICC_DECREMENT          0xC0
#define PICC_INCREMENT          0xC1
#define PICC_RESTORE            0xC2        // Transfer data to buffer
#define PICC_TRANSFER           0xB0        // Save buffer data
#define PICC_HALT               0x50        // Dormancy

// MIFARE constants
#define MF_ACK 0xA    // The MIFARE Classic uses a 4 bit ACK/NAK. Any other value than 0xA is NAK.
#define MF_KEY_SIZE 6 // A Mifare Crypto1 key is 6 bytes.

// PICC types we can detect.
enum PICC_Types {
    PICC_TYPE_UNKNOWN		,
    PICC_TYPE_ISO_14443_4	,	// PICC compliant with ISO/IEC 14443-4 
    PICC_TYPE_ISO_18092		, 	// PICC compliant with ISO/IEC 18092 (NFC)
    PICC_TYPE_MIFARE_MINI	,	// MIFARE Classic protocol, 320 bytes
    PICC_TYPE_MIFARE_1K		,	// MIFARE Classic protocol, 1KB
    PICC_TYPE_MIFARE_4K		,	// MIFARE Classic protocol, 4KB
    PICC_TYPE_MIFARE_UL		,	// MIFARE Ultralight or Ultralight C
    PICC_TYPE_MIFARE_PLUS	,	// MIFARE Plus
    PICC_TYPE_MIFARE_DESFIRE,	// MIFARE DESFire
    PICC_TYPE_TNP3XXX		,	// Only mentioned in NXP AN 10833 MIFARE Type Identification Procedure
    PICC_TYPE_NOT_COMPLETE	= 0xff	// SAK indicates UID is not complete.
};

// MF522 Error code returned when communication
#define MI_OK 0
#define MI_NOTAGERR 1
#define MI_ERR 2

static const char *const _TypeNamePICC[] =
{
    "Unknown type",
    "PICC compliant with ISO/IEC 14443-4",
    "PICC compliant with ISO/IEC 18092 (NFC)",
    "MIFARE Mini, 320 bytes",
    "MIFARE 1KB",
    "MIFARE 4KB",
    "MIFARE Ultralight or Ultralight C",
    "MIFARE Plus",
    "MIFARE TNP3XXX",

    /* not complete UID */
    "SAK indicates UID is not complete"};

#define MFRC522_MaxPICCs (sizeof(_TypeNamePICC) / sizeof(_TypeNamePICC[0]))

//------------------MFRC522 Register---------------
// Page 0:Command and Status
#define Reserved00 0x00
#define CommandReg 0x01
#define CommIEnReg 0x02
#define DivlEnReg 0x03
#define CommIrqReg 0x04
#define DivIrqReg 0x05
#define ErrorReg 0x06
#define Status1Reg 0x07
#define Status2Reg 0x08
#define FIFODataReg 0x09
#define FIFOLevelReg 0x0A

#define WaterLevelReg 0x0B
#define ControlReg 0x0C
#define BitFramingReg 0x0D
#define CollReg 0x0E
#define Reserved01 0x0F
// Page 1:Command
#define Reserved10 0x10
#define ModeReg 0x11
#define TxModeReg 0x12
#define RxModeReg 0x13
#define TxControlReg 0x14
#define TxAutoReg 0x15
#define TxSelReg 0x16
#define RxSelReg 0x17
#define RxThresholdReg 0x18
#define DemodReg 0x19

#define Reserved11 0x1A
#define Reserved12 0x1B
#define MifareReg 0x1C
#define Reserved13 0x1D
#define Reserved14 0x1E
#define SerialSpeedReg 0x1F
// Page 2:CFG
#define Reserved20 0x20
#define CRCResultRegM 0x21
#define CRCResultRegL 0x22
#define Reserved21 0x23
#define ModWidthReg 0x24
#define Reserved22 0x25
#define RFCfgReg 0x26
#define GsNReg 0x27
#define CWGsPReg 0x28
#define ModGsPReg 0x29
#define TModeReg 0x2A
#define TPrescalerReg 0x2B
#define TReloadRegH 0x2C
#define TReloadRegL 0x2D
#define TCounterValueRegH 0x2E
#define TCounterValueRegL 0x2F
// Page 3:TestRegister
#define Reserved30 0x30

#define TestSel1Reg 0x31
#define TestSel2Reg 0x32
#define TestPinEnReg 0x33
#define TestPinValueReg 0x34
#define TestBusReg 0x35
#define AutoTestReg 0x36
#define VersionReg 0x37
#define AnalogTestReg 0x38
#define TestDAC1Reg 0x39
#define TestDAC2Reg 0x3A
#define TestADCReg 0x3B
#define Reserved31 0x3C
#define Reserved32 0x3D
#define Reserved33 0x3E
#define Reserved34 0x3F


/////////////////////////////////////////////////////////////////////////////////////
// Functions for manipulating the MFRC522
/////////////////////////////////////////////////////////////////////////////////////
int pcd_init(struct rc522_data *rc522);
int pcd_get_version(struct rc522_data *rc522);
void pcd_release(struct rc522_data *rc522);

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with PICCs
/////////////////////////////////////////////////////////////////////////////////////
int pcd_request_card(struct rc522_data *rc522, u8 req_mode);
int pcd_anticoll_card(struct rc522_data *rc522, struct rc522_card_info *card);
int pcd_select_tag(struct rc522_data *rc522, struct rc522_card_info *card);
int pcd_try_key(struct rc522_data *rc522, struct rc522_card_info *card);
int pcd_read_data(struct rc522_data *rc522, struct rc522_card_info *card);
int pcd_write_data(struct rc522_data *rc522, struct rc522_card_info *card);
void pcd_halt(struct rc522_data *rc522);


void pcd_test_read_card(struct rc522_data *rc522);

#endif // RC522_API_MODULE_H