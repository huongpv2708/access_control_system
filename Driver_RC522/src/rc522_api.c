#include "rc522_main.h"
#include "rc522_api.h"

/////////////////////////////////////////////////////////////////////////////////////
// Basic interface functions for communicating with the MFRC522
/////////////////////////////////////////////////////////////////////////////////////
int pcd_write_register(struct spi_device *spi, u8 reg, u8 value);
int pcd_read_register(struct spi_device *spi, u8 reg, u8 *value);
int pcd_set_bitmask(struct spi_device *spi, u8 reg, u8 mask);
int pcd_clear_bitmask(struct spi_device *spi, u8 reg, u8 mask);
int pcd_calculate_crc(struct rc522_data *data, u8 *in_data, u8 len, u8 *out_data);

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with PICCs
/////////////////////////////////////////////////////////////////////////////////////
int pcd_transceive(struct spi_device *spi, u8 cmd, u8 *send_data, u8 send_len, u8 *back_data, u8 *back_len);
void pcd_antenna_off(struct spi_device *spi);
void pcd_antenna_on(struct spi_device *spi);
void pcd_reset(struct spi_device *spi);

/////////////////////////////////////////////////////////////////////////////////////
// Functions for communicating with MIFARE PICCs
/////////////////////////////////////////////////////////////////////////////////////
int pcd_authen(u8 cmd, u8 blockAddr, struct rc522_data *data, struct rc522_card_info *card);
int mifare_read(struct rc522_data *rc522, u8 block_addr, u8 *buffer, u8 *buffer_size);
int mifare_write(struct rc522_data *rc522, u8 block_addr, u8 *buffer, u8 buffer_size);
// StatusCode MIFARE_Decrement(byte blockAddr, int32_t delta);
// StatusCode MIFARE_Increment(byte blockAddr, int32_t delta);
// StatusCode MIFARE_Restore(byte blockAddr);
// StatusCode MIFARE_Transfer(byte blockAddr);
// StatusCode MIFARE_GetValue(byte blockAddr, int32_t *value);
// StatusCode MIFARE_SetValue(byte blockAddr, int32_t value);

/////////////////////////////////////////////////////////////////////////////////////
// Support functions
/////////////////////////////////////////////////////////////////////////////////////
uint8_t picc_get_type(uint8_t sak);
char *picc_get_type_name(uint8_t picc_type);

// Function to write a value to a register
// returns 0 on success, -ve on failure
int pcd_write_register(struct spi_device *spi, u8 reg, u8 value)
{
    int ret;
    u8 tx_buf[2];

    tx_buf[0] = ((reg << 1) & 0x7E);
    tx_buf[1] = value;
    ret = spi_write(spi, tx_buf, 2);
    if (ret != 0)
        dev_err(&spi->dev, "RC522 Driver: failed to write reg: addr=0x%02x, value=0x%02x, ret = %d\n", reg, value, ret);
    return ret;
}

// Function to read a value from a register
// returns 0 on success, -ve on failure
int pcd_read_register(struct spi_device *spi, u8 reg, u8 *value)
{
    u8 tx_buf[2];
    u8 rx_buf[2];
    int ret;

    /* Construct the read command */
    tx_buf[0] = ((reg << 1) & 0x7E) | 0x80;
    tx_buf[1] = 0x00;

    struct spi_transfer t = {
        .tx_buf = tx_buf,
        .rx_buf = rx_buf,
        .len = 2,
    };
    struct spi_message m;
    spi_message_init(&m);
    spi_message_add_tail(&t, &m);

    ret = spi_sync(spi, &m);
    if (ret < 0)
    {
        dev_err(&spi->dev, "SPI read error: %d\n", ret);
        return ret;
    }

    *value = rx_buf[1];
    return 0;
}

// Helper Functions for Bitmask Operations:
int pcd_set_bitmask(struct spi_device *spi, u8 reg, u8 mask)
{
    u8 tmp;
    pcd_read_register(spi, reg, &tmp);
    tmp |= mask;
    return pcd_write_register(spi, reg, tmp);
}

int pcd_clear_bitmask(struct spi_device *spi, u8 reg, u8 mask)
{
    u8 tmp;
    pcd_read_register(spi, reg, &tmp);
    tmp &= (~mask);
    return pcd_write_register(spi, reg, tmp);
}

/*
 * Function Name: pcd_reset
 * Description: Reset RC522
 * Input: spi_device *spi
 * Return value: None
 */
void pcd_reset(struct spi_device *spi)
{
    pcd_write_register(spi, CommandReg, PCD_SoftReset);
}

// Function to perform a read/write operations on the RC522
// return 0 on success, -ve on failure
int pcd_test_write_read(struct spi_device *spi)
{
    u8 test_reg = SerialSpeedReg; // Any register that supports write/read operations, e.g., SerialSpeedReg
    u8 write_val = 0x74;          // 0x55 is arbitrary
    u8 read_val = 0x00;

    // Step 1: Write to the register
    int ret = pcd_write_register(spi, test_reg, write_val);
    if (ret)
    {
        dev_err(&spi->dev, "Write failed with error %d\n", ret);
        return ret;
    }

    // Step 2: Read back from the same register
    ret = pcd_read_register(spi, test_reg, &read_val);
    if (ret)
    {
        dev_err(&spi->dev, "Read failed with error %d\n", ret);
        return ret;
    }

    // Step 3: Compare the written value with the read value
    if (read_val == write_val)
    {
        ret = 0;
        dev_info(&spi->dev, "Write/Read test passed.\n");
    }
    else
    {
        ret = -1;
        dev_err(&spi->dev, "Write/Read test failed. Written: 0x%02x, Read: 0x%02x\n", write_val, read_val);
    }
    return ret;
}

/* -------------------------------------------------------------- */
//  check if an RFID card is present.
/**
 * @brief
 *
 * @param spi
 * @param cmd
 * @param send_data
 * @param sendLen
 * @param backData
 * @param backLen
 * @return MI_OK on success, MI_ERR, MI_NOTAGERR on failure
 */
int pcd_transceive(struct spi_device *spi, u8 cmd, u8 *send_data, u8 send_len, u8 *back_data, u8 *back_len)
{
    // dev_info(&spi->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    int status = MI_ERR;
    u8 irqEn = 0x00; // Enable all interrupts
    u8 waitIRq = 0x00;
    u8 n;
    u32 i;
    switch (cmd)
    {
    case PCD_MFAuthent:
    {
        irqEn = 0x12;
        waitIRq = 0x10;
        break;
    }
    case PCD_Transceive:
    {
        irqEn = 0x77;
        waitIRq = 0x30;
        break;
    }
    default:
        break;
    }

    pcd_write_register(spi, CommIEnReg, irqEn | 0x80); // Enable interrupts
    pcd_clear_bitmask(spi, CommIrqReg, 0x80);          // Clear all interrupt flags
    pcd_set_bitmask(spi, FIFOLevelReg, 0x80);          // Flush FIFO buffer

    pcd_write_register(spi, CommandReg, PCD_Idle); // No action, cancel current command

    // Writing data to the FIFO
    for (i = 0; i < send_len; i++)
    {
        pcd_write_register(spi, FIFODataReg, send_data[i]);
    }

    // Execute the command
    pcd_write_register(spi, CommandReg, cmd); // Start transmission
    if (cmd == PCD_Transceive)
        pcd_set_bitmask(spi, BitFramingReg, 0x80); // Start Send

    // Waiting to receive data to complete
    i = 2000; // Timeout counter
    do
    {
        pcd_read_register(spi, CommIrqReg, &n);
        i--;
    } while ((i != 0) && !(n & 0x01) && !(n & waitIRq));

    pcd_clear_bitmask(spi, BitFramingReg, 0x80); // Stop Send
    // dev_info(&spi->dev, "i = %d; n = 0x%02X; n = %d\n", i, n, n);

    if (i != 0)
    {
        // dev_info(&spi->dev, "i != 0; line = %d\n", __LINE__);
        u8 error;
        pcd_read_register(spi, ErrorReg, &error);
        if (!(error & 0x1B))
        {
            // dev_info(&spi->dev, "!(error & 0x1B); line = %d\n", __LINE__);
            status = MI_OK;
            if (n & irqEn & 0x01)
            {
                dev_err(&spi->dev, "(n & irqEn & 0x01); line = %d\n", __LINE__);
                status = MI_NOTAGERR;
            }

            if (cmd == PCD_Transceive)
            {
                u8 lastBits;
                pcd_read_register(spi, FIFOLevelReg, &n);
                pcd_read_register(spi, ControlReg, &lastBits);
                lastBits = lastBits & 0x07;
                if (lastBits)
                {
                    *back_len = (n - 1) * 8 + lastBits;
                }
                else
                {
                    *back_len = n * 8;
                }

                if (n == 0)
                {
                    n = 1;
                }
                if (n > RC522_MAX_LEN)
                {
                    n = RC522_MAX_LEN;
                }
                // dev_info(&spi->dev, "(cmd == PCD_Transceive); line = %d, n = %d, lastBits = 0x%02X, back_len = %d\n", __LINE__, n, lastBits, *back_len);
                // Reading the received data in FIFO
                for (i = 0; i < n; i++)
                {
                    pcd_read_register(spi, FIFODataReg, &back_data[i]);
                    // dev_info(&spi->dev, "(cmd == PCD_Transceive); line = %d, back_data[%d] = 0x%02X\n", __LINE__, i, back_data[i]);
                }
            }
        }
        else
        {
            dev_err(&spi->dev, "(error & 0x1B); line = %d\n", __LINE__);
            status = MI_ERR;
        }
    }

    pcd_write_register(spi, CommandReg, PCD_Idle); // No action, cancel current command
    return status;
}

void pcd_antenna_off(struct spi_device *spi)
{
    pcd_clear_bitmask(spi, TxControlReg, 0x03);
}
void pcd_antenna_on(struct spi_device *spi)
{
    u8 value;
    pcd_read_register(spi, TxControlReg, &value);
    if ((value & 0x03) != 0x03)
    {
        pcd_write_register(spi, TxControlReg, value | 0x03);
    }
}

/**
 * @brief
 *
 * @param spi
 * @param req_mode
 * @param tag_type
 * @return MI_OK on card exist, MI_ERR on error
 */
int pcd_request_card(struct rc522_data *rc522, u8 req_mode)
{
    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    int status;
    u8 back_bits;
    u8 tag_type[10];
    /* Send the REQA command */
    pcd_clear_bitmask(rc522->spi_dev, Status2Reg, 0x08);
    pcd_write_register(rc522->spi_dev, BitFramingReg, 0x07); // Set bit framing
    pcd_set_bitmask(rc522->spi_dev, TxControlReg, 0x03);
    tag_type[0] = req_mode;
    status = pcd_transceive(rc522->spi_dev, PCD_Transceive, tag_type, 1, tag_type, &back_bits);
    if ((status != MI_OK) || (back_bits != 0x10))
    {
        status = MI_ERR;
    }

    return status;
}

/* Function name: rc522_detect
 * @return version > 0  on success , -ve of failure
 */
int pcd_get_version(struct rc522_data *rc522)
{
    int ret;
    u8 version;

    ret = pcd_read_register(rc522->spi_dev, VersionReg, &version);
    if (ret < 0)
        return ret;

    switch (version)
    {
    case MFRC522_VERSION_1:
    case MFRC522_VERSION_2:
        dev_info(&rc522->spi_dev->dev, "MFRC522 version 0x%2X detected", version);
        return version;
    default:
        dev_warn(&rc522->spi_dev->dev, "This chip is not an MFRC522: 0x%2X", version);
    }
    return -1;
}

/**
 * @brief initialize RC522 device
 *
 * @param spi
 * @return 0 on success, -ve on failure
 */
int pcd_init(struct rc522_data *rc522)
{
    /* Reset the RC522 */
    if (rc522->reset_gpio)
    {
        gpiod_set_value(rc522->reset_gpio, 1);
        msleep(10);
        gpiod_set_value(rc522->reset_gpio, 0);
        msleep(5);
        gpiod_set_value(rc522->reset_gpio, 1);
        msleep(50);
    }

    /* Test read write register */
    int ret = pcd_test_write_read(rc522->spi_dev);
    if (ret)
    {
        dev_err(&rc522->spi_dev->dev, "RC522 Driver: Failed to write/read test: %d\n", ret);
        return ret;
    }

    /* Rest PCD */
    pcd_reset(rc522->spi_dev);
    pcd_write_register(rc522->spi_dev, TxModeReg, 0x00); // Reset baud rates
    pcd_write_register(rc522->spi_dev, RxModeReg, 0x00);
    // Reset ModWidthReg
    pcd_write_register(rc522->spi_dev, ModWidthReg, 0x26);

    // When communicating with a PICC we need a timeout if something goes wrong.
    // f_timer = 13.56 MHz / (2*TPreScaler+1) where TPreScaler = [TPrescaler_Hi:TPrescaler_Lo].
    // TPrescaler_Hi are the four low bits in TModeReg. TPrescaler_Lo is TPrescalerReg.
    pcd_write_register(rc522->spi_dev, TModeReg, 0x80);      // TAuto=1; timer starts automatically at the end of the transmission in all communication modes at all speeds
    pcd_write_register(rc522->spi_dev, TPrescalerReg, 0xA9); // TPreScaler = TModeReg[3..0]:TPrescalerReg, ie 0x0A9 = 169 => f_timer=40kHz, ie a timer period of 25μs.
    pcd_write_register(rc522->spi_dev, TReloadRegH, 0x03);   // Reload timer with 0x3E8 = 1000, ie 25ms before timeout.
    pcd_write_register(rc522->spi_dev, TReloadRegL, 0xE8);

    pcd_write_register(rc522->spi_dev, TxAutoReg, 0x40); // Default 0x00. Force a 100 % ASK modulation independent of the ModGsPReg register setting
    pcd_write_register(rc522->spi_dev, ModeReg, 0x3D);   // Default 0x3F. Set the preset value for the CRC coprocessor for the CalcCRC command to 0x6363 (ISO 14443-3 part 6.2.4)
    pcd_antenna_on(rc522->spi_dev);

    dev_info(&rc522->spi_dev->dev, "RC522 hardware initialization completed successfully.\n");
    return 0;
}

void pcd_release(struct rc522_data *rc522)
{
    pcd_antenna_off(rc522->spi_dev);
    dev_info(&rc522->spi_dev->dev, "RC522 hardware release completed successfully.\n");
}

/**
 * @brief
 *
 * @param data
 * @return MI_OK  on success, otherwise MI_ERR
 */
int pcd_anticoll_card(struct rc522_data *data, struct rc522_card_info *card)
{
    // dev_info(&data->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    int status;
    u8 uid_length = 0;
    u8 back_bits;
    u8 id_csum = 0;
    u8 i;
    u8 *rx_buff = card->rx_buffer;
    u8 *tx_buff = card->tx_buffer;
    tx_buff[0] = PICC_ANTICOLL;
    tx_buff[1] = 0x20;
    pcd_clear_bitmask(data->spi_dev, Status2Reg, 0x08);
    pcd_write_register(data->spi_dev, BitFramingReg, 0x00);
    pcd_clear_bitmask(data->spi_dev, CollReg, 0x80);

    status = pcd_transceive(data->spi_dev, PCD_Transceive, tx_buff, 2, rx_buff, &back_bits);
    if (status == MI_OK)
    {
        if (back_bits == 0x28)
        { // 4-byte UID (32 bits) + 1 byte crc
            uid_length = 4;
        }
        else if (back_bits == 0x46)
        { // 7-byte UID (56 bits) +1 byte crc
            uid_length = 7;
        }
        else
        {
            uid_length = 0;
            status = MI_ERR; // Unexpected UID length
        }
        for (i = 0; i < uid_length; i++)
        {
            id_csum ^= rx_buff[i];
            card->uid_bytes[i] = rx_buff[i];
        }
        if (id_csum != rx_buff[uid_length])
            status = MI_ERR;
    }
    card->uid_length = uid_length;
    pcd_set_bitmask(data->spi_dev, CollReg, 0x80);
    return status;
}

/**
 * @brief
 *
 * @param data
 * @param pIndata
 * @param len
 * @param pOutData
 * @return 0 on success, -1 on failure
 */
int pcd_calculate_crc(struct rc522_data *data, u8 *in_data, u8 len, u8 *out_data)
{
    int i;
    u8 reg_val = 0;
    pcd_clear_bitmask(data->spi_dev, DivIrqReg, 0x04);
    pcd_write_register(data->spi_dev, CommandReg, PCD_Idle);
    pcd_set_bitmask(data->spi_dev, FIFOLevelReg, 0x80);

    for (i = 0; i < len; i++)
        pcd_write_register(data->spi_dev, FIFODataReg, *(in_data + i));
    pcd_write_register(data->spi_dev, CommandReg, PCD_CalcCRC);

    i = 5000;
    do
    {
        pcd_read_register(data->spi_dev, DivIrqReg, &reg_val);
        msleep(30);
        i--;
    } while ((i != 0) && !(reg_val & 0x04)); // CRCIrq = 1

    pcd_write_register(data->spi_dev, CommandReg, PCD_Idle);

    pcd_read_register(data->spi_dev, CRCResultRegL, &out_data[0]);
    pcd_read_register(data->spi_dev, CRCResultRegM, &out_data[1]);
    return i > 0 ? 0 : -1;
}

/**
 * @brief
 *
 * @param data
 * @param card
 * @return MI_OK on success, MI_ERR on failure
 */
int pcd_select_tag(struct rc522_data *data, struct rc522_card_info *card)
{
    // dev_info(&data->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    int i = 0;
    u8 temp_buff[10] = {};
    int status;
    u8 back_bits;
    uint8_t size;
    temp_buff[0] = PICC_SElECTTAG;
    temp_buff[1] = 0x70;
    // dev_info(&data->spi_dev->dev, "%s(), line: %d, card->uid_length = %d\n", __FUNCTION__, __LINE__, card->uid_length);
    for (i = 0; i < card->uid_length + 1; i++)
    {
        temp_buff[2 + i] = card->rx_buffer[i];
    }
    int len = 2 + card->uid_length + 1;
    status = pcd_calculate_crc(data, temp_buff, len, &temp_buff[len]);
    // for (int i = 0; i < len + 2; i++)
    // {
    //     dev_info(&data->spi_dev->dev, "%s(), line: %d, temp_buff[%d] = 0x%02X\n", __FUNCTION__, __LINE__, i, temp_buff[i]);
    // }
    status = pcd_transceive(data->spi_dev, PCD_Transceive, temp_buff, len + 2, temp_buff, &back_bits);
    // dev_info(&data->spi_dev->dev, "%s(), line: %d, back_bits = 0X%02x.\n", __FUNCTION__, __LINE__, back_bits);
    if ((status == MI_OK) && (back_bits == 0x18))
    {
        if (temp_buff[0] == 0x00)
        {
            dev_warn(&data->spi_dev->dev, "UID complete, PICC not compliant with ISO/IEC 14443-4.\n");
            return MI_OK;
        }
        size = temp_buff[0];
        uint8_t picc_type = picc_get_type(size);
        char *picc_name = picc_get_type_name(picc_type);
        dev_info(&data->spi_dev->dev, "Type card inserted: %s.\n", picc_name);

        card->type = picc_type;
    }
    else
    {
        dev_err(&data->spi_dev->dev, "%s(), line: %d.\n", __FUNCTION__, __LINE__);
        size = 0;
    }
    return size > 0 ? MI_OK : MI_ERR;
}

int pcd_authen(u8 cmd, u8 blockAddr, struct rc522_data *data, struct rc522_card_info *card)
{
    // dev_info(&data->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    u8 temp_buff[12];
    uint8_t i = 0, len = 0;
    int status;
    u8 back_bits;

    temp_buff[0] = cmd;
    temp_buff[1] = blockAddr;
    len += 2;

    for (i = 0; i < MF_KEY_SIZE; i++)
    { // 6 key bytes
        temp_buff[len + i] = card->key_bytes[i];
    }
    len += MF_KEY_SIZE;

    for (i = 0; i < CARD_ID_SIZE; i++)
    {
        temp_buff[len + i] = card->uid_bytes[i];
    }
    len += CARD_ID_SIZE;

    // for (int i = 0; i < len; i++)
    // {
    //     dev_info(&data->spi_dev->dev, "%s(), line: %d, temp_buff[%d] = 0x%02X\n", __FUNCTION__, __LINE__, i, temp_buff[i]);
    // }

    status = pcd_transceive(data->spi_dev, PCD_MFAuthent, temp_buff, len, temp_buff, &back_bits);
    // dev_info(&data->spi_dev->dev, "%s(), line: %d, back_bits = 0x%02X, back_bits = %d\n", __FUNCTION__, __LINE__, back_bits, back_bits);

    return status;
}

int pcd_try_key(struct rc522_data *data, struct rc522_card_info *card)
{
    // dev_info(&data->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    u8 temp_buff[18];
    int status;
    u8 block_addr = 0;

    status = pcd_authen(PICC_AUTHENT1A, block_addr, data, card);
    if (status != MI_OK)
    {
        dev_err(&data->spi_dev->dev, "%s(), Line = %d, Failed to authenticate.\n", __FUNCTION__, __LINE__);
        return status;
    }

    u8 buff_size = sizeof(temp_buff);
    status = mifare_read(data, block_addr, temp_buff, &buff_size);
    if (status != MI_OK)
    {
        dev_err(&data->spi_dev->dev, "%s(), Line = %d, Failed to read data.\n", __FUNCTION__, __LINE__);
    }
    else
    {
        // dev_info(&data->spi_dev->dev, "%s(), Line = %d, Success with key:\n", __FUNCTION__, __LINE__);
        // for (int i = 0; i < MF_KEY_SIZE; i++)
        // { // 6 key bytes
        //     dev_info(&data->spi_dev->dev, "%s(), Line = %d, card->key_bytes[%d] = 0x%02X\n", __FUNCTION__, __LINE__, i, card->key_bytes[i]);
        // }
    }

    return status;
}

void pcd_test_read_card(struct rc522_data *data)
{
    int i = 5;
    int ret = MI_ERR;
    while (i--)
    {
        ret = pcd_request_card(data, PICC_REQIDL);
        if (ret == MI_OK)
        {
            break;
        }
        msleep(10);
    }
    if (ret != MI_OK)
    {
        dev_err(&data->spi_dev->dev, " No card detected after multiple attempts\n");
        return;
    }

    struct rc522_card_info card_info;
    ret = pcd_anticoll_card(data, &card_info);
    if (ret != MI_OK)
    {
        dev_err(&data->spi_dev->dev, " Failed to retrieve card UID (anti-collision failed)\n");
    }
    else
    {
        dev_info(&data->spi_dev->dev, "Card UID:");

        for (int i = 0; i < card_info.uid_length; i++)
        {
            printk(" 0x%02x", card_info.rx_buffer[i]);
        }
        printk("\n");
    }
    ret = pcd_select_tag(data, &card_info);
}
void pcd_halt(struct rc522_data *rc522)
{
    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d.\n", __FUNCTION__, __LINE__);
    u8 status;
    u8 back_bits;
    u8 buff[4];

    buff[0] = PICC_HALT;
    buff[1] = 0;
    pcd_calculate_crc(rc522, buff, 2, &buff[2]);
    status = pcd_transceive(rc522->spi_dev, PCD_Transceive, buff, 4, buff, &back_bits);
}

int mifare_read(struct rc522_data *rc522, u8 block_addr, u8 *buffer, u8 *buffer_size)
{
    if (buffer == NULL || *buffer_size < 18)
        return MI_ERR;

    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d, bufferSize = %d.\n", __FUNCTION__, __LINE__, *buffer_size);
    int status;
    u8 back_bits;
    buffer[0] = PICC_READ;
    buffer[1] = block_addr;

    status = pcd_calculate_crc(rc522, buffer, 2, &buffer[2]);
    if (status != MI_OK)
        return status;

    status = pcd_transceive(rc522->spi_dev, PCD_Transceive, buffer, 4, buffer, &back_bits);
    return status;
}

int mifare_write(struct rc522_data *rc522, u8 block_addr, u8 *buffer, u8 buffer_size)
{
    if (buffer == NULL || buffer_size > 16)
    {
        return MI_ERR;
    }

    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d, buffer_size = %d.\n", __FUNCTION__, __LINE__, buffer_size);
    int status, len = 0;
    u8 back_bits;
    u8 cmd_buffer[18];

    // Mifare Classic protocol requires two communications to perform a write.
    // Step 1: Tell the PICC we want to write to block blockAddr.
    cmd_buffer[0] = PICC_WRITE;
    cmd_buffer[1] = block_addr;
    len += 2;

    status = pcd_calculate_crc(rc522, cmd_buffer, len, &cmd_buffer[len]);
    if (status != MI_OK)
        return status;
    len += 2;

    status = pcd_transceive(rc522->spi_dev, PCD_Transceive, cmd_buffer, len, cmd_buffer, &back_bits);
    if (status != MI_OK)
        return status;
    // The PICC must reply with a 4 bit ACK
    if (back_bits != 4)
    {
        return MI_ERR;
    }
    if (cmd_buffer[0] != MF_ACK)
    {
        return MI_ERR;
    }

    // Step 2: Transfer the data
    memset(cmd_buffer, 0, sizeof(cmd_buffer));
    len = 0;
    for (int i = 0; i < buffer_size; i++)
    {
        cmd_buffer[i] = buffer[i];
    }
    len += buffer_size;
    status = pcd_calculate_crc(rc522, cmd_buffer, len, &cmd_buffer[len]);
    if (status != MI_OK)
        return status;
    len += 2;

    // for (int i = 0; i < len; i++)
    // {
    //     dev_info(&rc522->spi_dev->dev, "%s(), line: %d, cmd_buffer[%d] = 0x%02X.\n", __FUNCTION__, __LINE__, i, cmd_buffer[i]);
    // }

    status = pcd_transceive(rc522->spi_dev, PCD_Transceive, cmd_buffer, len, cmd_buffer, &back_bits);
    if (status != MI_OK)
        return status;
    // The PICC must reply with a 4 bit ACK
    if (back_bits != 4)
    {
        return MI_ERR;
    }
    if (cmd_buffer[0] != MF_ACK)
    {
        return MI_ERR;
    }

    return status;
}

int pcd_read_data(struct rc522_data *rc522, struct rc522_card_info *card)
{
    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d, blockaddr_read = %d.\n", __FUNCTION__, __LINE__, card->blockaddr_read);
    u8 temp_buff[18];
    int status;
    u8 buff_size = sizeof(temp_buff);
    u8 trailerBlock = card->blockaddr_read / 4 * 4;

    status = pcd_authen(PICC_AUTHENT1A, trailerBlock, rc522, card);
    if (status != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "%s(), Line = %d, Failed to authenticate.\n", __FUNCTION__, __LINE__);
        return status;
    }
    status = mifare_read(rc522, card->blockaddr_read, temp_buff, &buff_size);
    if (status != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "%s(), Line = %d, Failed to read data.\n", __FUNCTION__, __LINE__);
        return status;
    }
    for (int i = 0; i < DATA_BUFFER_SIZE; i++)
    {
        card->data_read[i] = temp_buff[i];
    }
    return status;
}

// Function to write data to the card
int pcd_write_data(struct rc522_data *rc522, struct rc522_card_info *card)
{
    // dev_info(&rc522->spi_dev->dev, "%s() is invoked, line: %d, blockaddr_write = %d.\n", __FUNCTION__, __LINE__, card->blockaddr_write);
    int status;
    u8 block_addr = card->blockaddr_write;
    u8 sector = block_addr / 4;
    u8 trailerBlock = 4 * sector + 3;

    status = pcd_authen(PICC_AUTHENT1A, trailerBlock, rc522, card);
    if (status != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "%s(), Line = %d, Failed to authenticate.\n", __FUNCTION__, __LINE__);
        return status;
    }

    u8 buff_size = DATA_BUFFER_SIZE;
    status = mifare_write(rc522, block_addr, card->data_write, buff_size);
    if (status != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "%s(), Line = %d, Failed to write data.\n", __FUNCTION__, __LINE__);
    }
    else
    {
        // dev_info(&rc522->spi_dev->dev, "%s(), Line = %d, Write success, data:\n", __FUNCTION__, __LINE__);
        // for (int i = 0; i < buff_size; i++)
        // {
        //     dev_info(&rc522->spi_dev->dev, "%s(), Line = %d, card->data_write[%d] = 0x%02X\n", __FUNCTION__, __LINE__, i, card->data_write[i]);
        // }
    }

    return status;
}

/**
 * Translates the SAK (Select Acknowledge) to a PICC type.
 *
 * @param sak The SAK byte returned from PICC_Select().
 *
 * @return PICC_Type
 */
uint8_t picc_get_type(uint8_t sak)
{
    uint8_t retType = PICC_TYPE_UNKNOWN;

    if (sak & 0x04)
    { // UID not complete
        retType = PICC_TYPE_NOT_COMPLETE;
    }
    else
    {
        switch (sak)
        {
        case 0x09:
            retType = PICC_TYPE_MIFARE_MINI;
            break;
        case 0x08:
            retType = PICC_TYPE_MIFARE_1K;
            break;
        case 0x18:
            retType = PICC_TYPE_MIFARE_4K;
            break;
        case 0x00:
            retType = PICC_TYPE_MIFARE_UL;
            break;
        case 0x10:
        case 0x11:
            retType = PICC_TYPE_MIFARE_PLUS;
            break;
        case 0x01:
            retType = PICC_TYPE_TNP3XXX;
            break;
        default:
            if (sak & 0x20)
            {
                retType = PICC_TYPE_ISO_14443_4;
            }
            else if (sak & 0x40)
            {
                retType = PICC_TYPE_ISO_18092;
            }
            break;
        }
    }

    return (retType);
}

/**
 * Returns a string pointer to the PICC type name.
 *
 * @param type One of the PICC_Type enums.
 *
 * @return A string pointer to the PICC type name.
 */
char *picc_get_type_name(uint8_t picc_type)
{
    if (picc_type == PICC_TYPE_NOT_COMPLETE)
    {
        picc_type = MFRC522_MaxPICCs - 1;
    }

    return ((char *)_TypeNamePICC[picc_type]);
}
