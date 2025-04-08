#include "rc522_main.h"
#include "rc522_api.h"
#include <linux/ioctl.h>

#define RC522_IOC_MAGIC 'r'
#define RC522_IOC_GET_UID _IOR(RC522_IOC_MAGIC, 1, struct rc522_card_info)
#define RC522_IOC_GET_KEY _IOR(RC522_IOC_MAGIC, 2, struct rc522_card_info)
#define RC522_IOC_WRITE_DATA _IOW(RC522_IOC_MAGIC, 3, struct rc522_card_info)
#define RC522_IOC_READ_DATA _IOWR(RC522_IOC_MAGIC, 4, struct rc522_card_info)

u8 knownKeys[NR_KNOWN_KEYS][MF_KEY_SIZE] = {
    {0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, // FF FF FF FF FF FF = factory default
    {0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5}, // A0 A1 A2 A3 A4 A5
    {0xb0, 0xb1, 0xb2, 0xb3, 0xb4, 0xb5}, // B0 B1 B2 B3 B4 B5
    {0x4d, 0x3a, 0x99, 0xc3, 0x51, 0xdd}, // 4D 3A 99 C3 51 DD
    {0x1a, 0x98, 0x2c, 0x7e, 0x45, 0x9a}, // 1A 98 2C 7E 45 9A
    {0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7}, // D3 F7 D3 F7 D3 F7
    {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff}, // AA BB CC DD EE FF
    {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}  // 00 00 00 00 00 00
};

static int Device_Open = 0;
static dev_t devt;
static struct class *rc522_class;
static struct rc522_card_info card_info;

int rc522_open(struct inode *, struct file *);
int rc522_release(struct inode *, struct file *);
ssize_t rc522_read(struct file *, char __user *, size_t, loff_t *);
ssize_t rc522_write(struct file *, const char __user *, size_t, loff_t *);
long rc522_ioctl(struct file *filep, unsigned int cmd, unsigned long arg);
const struct file_operations rc522_fops = {
    .owner = THIS_MODULE,
    .open = rc522_open,
    .release = rc522_release,
    .read = rc522_read,
    .write = rc522_write,
    .unlocked_ioctl = rc522_ioctl,
};

/**
 * @brief Open RC522 device node
 *
 * @param inode
 * @param file
 * @return 0 on success, -ve on failure
 */
int rc522_open(struct inode *inode, struct file *file)
{
    if (Device_Open)
    {
        pr_err("%s: Cannot open, device is busy.\n", DEVICE_NAME);
        return -EBUSY;
    }
    Device_Open++;

    struct rc522_data *rc522;
    rc522 = container_of(inode->i_cdev, struct rc522_data, cdev);
    if (!rc522)
    {
        pr_err("%s: No device in rc522 data\n", DEVICE_NAME);
        return -ENODEV;
    }
    file->private_data = rc522;

    /* Initialize RC522 hardware */
    if (rc522->version == 0)
    {
        int ret = pcd_init(rc522);
        if (ret)
        {
            pr_err("%s: Failed to initialize RC522: %d\n", DEVICE_NAME, ret);
            return -ENODEV;
        }
        int version = pcd_get_version(rc522);
        if (version < 0)
        {
            pr_err("%s: Cannot get the chip version: 0x%02X\n", DEVICE_NAME, version);
            return version;
        }
        rc522->version = version;
    }

    pr_info("%s: Device opened.\n", DEVICE_NAME);
    return 0;
}

int rc522_release(struct inode *inode, struct file *file)
{
    Device_Open--;
    memset(&card_info, 0, sizeof(card_info));
    struct rc522_data *rc522 = file->private_data;

    pcd_release(rc522);

    pr_info("%s: Device closed\n", DEVICE_NAME);
    return 0;
}

ssize_t rc522_read(struct file *file, char __user *buf, size_t count, loff_t *offset)
{
    // printk("%s: %s() is invoked.\n", DEVICE_NAME, __FUNCTION__);
    struct rc522_data *rc522 = file->private_data;

    memset(&card_info, 0, sizeof(card_info));

    // 1- Request the card
    int i = 5;
    int ret = MI_ERR;
    while (i--)
    {
        ret = pcd_request_card(rc522, PICC_REQIDL);
        if (ret == MI_OK)
        {
            break;
        }
        msleep(10);
    }
    if (ret != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "Failed to request to card.\n");
        return -EIO;
    }

    // 2- Perform anti-collision to get UID
    ret = pcd_anticoll_card(rc522, &card_info);
    if (ret != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "Failed to perform anti-collision.\n");
        return -EIO;
    }

    // 3- Select the tag
    ret = pcd_select_tag(rc522, &card_info);
    if (ret != MI_OK)
    {
        dev_err(&rc522->spi_dev->dev, "Failed to select tag.\n");
        return -EIO;
    }

    // Ensure user buffer is large enough
    if (count < card_info.uid_length)
    {
        dev_err(&rc522->spi_dev->dev, "User buffer is not large enough.\n");
        return -EINVAL;
    }

    // Copy UID to user-space buffer
    if (copy_to_user(buf, card_info.rx_buffer, card_info.uid_length))
    {
        dev_err(&rc522->spi_dev->dev, "Failed to copy data to user.\n");
        return -EFAULT;
    }

    return card_info.uid_length;
}

ssize_t rc522_write(struct file *file, const char __user *buf, size_t count, loff_t *offset)
{
    struct rc522_data *rc522 = file->private_data;
    if (copy_from_user(card_info.tx_buffer, (void __user *)buf, count))
    {
        dev_err(&rc522->spi_dev->dev, "Failed to copy data from user.\n");
        return -EFAULT;
    }

    dev_info(&rc522->spi_dev->dev, "Write to device count %lu ,offset %lld\n", count, *offset);
    return count;
}

long rc522_ioctl(struct file *filep, unsigned int cmd, unsigned long arg)
{
    struct rc522_data *rc522 = filep->private_data;
    int ret = MI_ERR;

    switch (cmd)
    {
    case RC522_IOC_GET_UID:
    {
        dev_info(&rc522->spi_dev->dev, "Execute RC522_IOC_GET_UID command.\n");

        memset(&card_info, 0, sizeof(card_info));
        int version = pcd_get_version(rc522);
        if (version < 0)
        {
            pr_err("%s: Cannot get the chip version: 0x%02X\n", DEVICE_NAME, version);
            return version;
        }
        card_info.version = version;

        int i = 5;
        while (i--)
        {
            ret = pcd_request_card(rc522, PICC_REQIDL);
            if (ret == MI_OK)
            {
                break;
            }
            msleep(10);
        }
        if (ret != MI_OK)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to request to card.\n");
            return -EIO;
        }

        ret = pcd_anticoll_card(rc522, &card_info);
        if (ret != MI_OK)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to perform anti-collision.\n");
            return -EIO;
        }

        ret = pcd_select_tag(rc522, &card_info);
        if (ret != MI_OK)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to select tag.\n");
            return -EIO;
        }

        card_info.initialized = true;

        if (copy_to_user((void __user *)arg, &card_info, sizeof(card_info)))
        {
            dev_err(&rc522->spi_dev->dev, "Failed to copy data to user space.\n");
            return -EFAULT;
        }
        
        return 0;
    }

    case RC522_IOC_GET_KEY:
    {
        dev_info(&rc522->spi_dev->dev, "Execute RC522_IOC_GET_KEY command.\n");

        if (card_info.initialized == false)
        {
            dev_err(&rc522->spi_dev->dev, "Card is not initialized.\n");
            return -EIO;
        }

        // Try the known default keys
        for (int k = 0; k < NR_KNOWN_KEYS; k++)
        {
            for (int i = 0; i < MF_KEY_SIZE; i++)
            {
                card_info.key_bytes[i] = knownKeys[k][i];
            }
            ret = pcd_try_key(rc522, &card_info);
            if (ret == MI_OK)
            {
                card_info.is_known_key = true;
                break;
            }
            card_info.is_known_key = false;
        }

        if (card_info.is_known_key == false)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to get key card.\n");
            return -EIO;
        }

        if (copy_to_user((void __user *)arg, &card_info, sizeof(card_info)))
        {
            dev_err(&rc522->spi_dev->dev, "Failed to copy data to user space.\n");
            return -EFAULT;
        }

        return 0;
    }

    case RC522_IOC_READ_DATA:
    {
        dev_info(&rc522->spi_dev->dev, "Execute RC522_IOC_READ_DATA command.\n");

        struct rc522_card_info temp_card_info;
        memset(&temp_card_info, 0, sizeof(temp_card_info));

        if (copy_from_user(&temp_card_info, (void __user *)arg, sizeof(temp_card_info)))
        {
            dev_err(&rc522->spi_dev->dev, "Failed to copy data from user space.\n");
            return -EFAULT;
        }

        if (card_info.initialized == false || card_info.is_known_key == false)
        {
            dev_err(&rc522->spi_dev->dev, "Card is not initialized or get the key.\n");
            return -EIO;
        }

        card_info.blockaddr_read = temp_card_info.blockaddr_read;

        // Read data from the card
        ret = pcd_read_data(rc522, &card_info);
        if (ret < 0)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to read data from card.\n");
            return ret;
        }

        // Copy the read data to user space
        if (copy_to_user((void __user *)arg, &card_info, sizeof(card_info)))
        {
            dev_err(&rc522->spi_dev->dev, "Failed to copy data to user space.\n");
            return -EFAULT;
        }

        return ret;
    }

    case RC522_IOC_WRITE_DATA:
    {
        dev_info(&rc522->spi_dev->dev, "Execute RC522_IOC_READ_DATA command.\n");

        struct rc522_card_info temp_card_info;
        memset(&temp_card_info, 0, sizeof(temp_card_info));

        if (copy_from_user(&temp_card_info, (void __user *)arg, sizeof(temp_card_info)))
        {
            dev_err(&rc522->spi_dev->dev, "Failed to copy data from user space.\n");
            return -EFAULT;
        }

        if (card_info.initialized == false || card_info.is_known_key == false)
        {
            dev_err(&rc522->spi_dev->dev, "Card is not initialized or get the key.\n");
            return -EIO;
        }

        card_info.blockaddr_write = temp_card_info.blockaddr_write;
        
        for (int i = 0; i < DATA_BUFFER_SIZE; i++)
        {
            card_info.data_write[i] = temp_card_info.data_write[i];
        }

        ret = pcd_write_data(rc522, &card_info);
        if (ret != MI_OK)
        {
            dev_err(&rc522->spi_dev->dev, "Failed to write data to card.\n");
            return -EIO;
        }
        return 0;
    }
    default:
    {
        dev_err(&rc522->spi_dev->dev, "Invalid command.\n");
        return -ENOTTY;
    }
    }
}

/*-------------------------------------------------------------------------*/

static int rc522_probe(struct spi_device *spi)
{
    // dev_info(&spi->dev, "%s is invoked.\n", __FUNCTION__);
    struct rc522_data *rc522;
    int ret;

    rc522 = devm_kzalloc(&spi->dev, sizeof(*rc522), GFP_KERNEL);
    if (!rc522)
    {
        dev_err(&spi->dev, "Failed to allocate device memory.\n");
        return -ENOMEM;
    }

    rc522->reset_gpio = devm_gpiod_get_optional(&spi->dev, "reset", GPIOD_OUT_HIGH);
    if (IS_ERR(rc522->reset_gpio))
    {
        ret = PTR_ERR(rc522->reset_gpio);
        dev_err(&spi->dev, "Failed to get reset GPIO: %d\n", ret);
        return ret;
    }

    /* Initialize the driver data */
    rc522->devt = devt;
    rc522->spi_dev = spi;
    rc522->version = 0;

    cdev_init(&rc522->cdev, &rc522_fops);
    rc522->cdev.owner = THIS_MODULE;

    /* Add cdev to the system */
    ret = cdev_add(&rc522->cdev, rc522->devt, 1);
    if (ret)
    {
        dev_err(&spi->dev, "Failed to add cdev\n");
        goto err_cdev_add;
    }

    /* Create device node */
    struct device *dev;
    dev = device_create(rc522_class, &spi->dev, rc522->devt, rc522, DEVICE_NAME);
    if (IS_ERR(dev))
    {
        dev_err(&spi->dev, "Failed to create device node\n");
        ret = PTR_ERR(dev);
        goto err_device_create;
    }

    /* Save driver data */
    spi_set_drvdata(spi, rc522);

    dev_info(&spi->dev, "RC522 probe function completed successfully.\n");
    return 0;

err_device_create:
    cdev_del(&rc522->cdev);
err_cdev_add:
    return ret;
}

static void rc522_remove(struct spi_device *spi)
{
    // dev_info(&spi->dev, "%s is invoked.\n", __FUNCTION__);
    struct rc522_data *rc522 = spi_get_drvdata(spi);
    if (rc522->reset_gpio)
        gpiod_direction_input(rc522->reset_gpio);
    device_destroy(rc522_class, rc522->devt);
    cdev_del(&rc522->cdev);
    dev_info(&spi->dev, "Device removed successfully.\n");
}

/*-------------------------------------------------------------------------*/
static const struct of_device_id rc522_of_match[] = {
    {.compatible = "nxp,rc522"},
    {}};

static struct spi_driver rc522_spi_driver = {
    .driver = {
        .name = DEVICE_NAME,
        .owner = THIS_MODULE,
        .of_match_table = rc522_of_match,
    },
    .probe = rc522_probe,
    .remove = rc522_remove,
};

/*-------------------------------------------------------------------------*/

static int __init rc522_init(void)
{
    int result;
    /* Allocate character device numbers */
    result = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME);
    if (result < 0)
    {
        pr_err("%s: Failed to allocate character device region.\n", DEVICE_NAME);
        return result;
    }
    pr_info("%s: Allocated Major = %d Minor = %d\n", DEVICE_NAME, MAJOR(devt), MINOR(devt));

    rc522_class = class_create(CLASS_NAME);
    if (IS_ERR(rc522_class))
    {
        pr_err("%s: Failed to create device class '%s'\n", DEVICE_NAME, CLASS_NAME);
        result = PTR_ERR(rc522_class);
        goto unregister_chrdev;
    }

    result = spi_register_driver(&rc522_spi_driver);
    if (result < 0)
    {
        pr_err("%s: Failed to register SPI driver.\n", DEVICE_NAME);
        goto destroy_class;
    }

    pr_info("%s: SPI driver registered successfully.\n", DEVICE_NAME);
    return 0;

destroy_class:
    class_destroy(rc522_class);
unregister_chrdev:
    unregister_chrdev_region(devt, 1);
    return result;
}

static void __exit rc522_exit(void)
{
    spi_unregister_driver(&rc522_spi_driver);
    class_destroy(rc522_class);
    unregister_chrdev_region(devt, 1);
    pr_info("%s: SPI driver unregistered and module exited.\n", DEVICE_NAME);
}

module_init(rc522_init);
module_exit(rc522_exit);

MODULE_DEVICE_TABLE(of, rc522_of_match);

MODULE_AUTHOR("Huongpham");
MODULE_DESCRIPTION("A Linux SPI Device Driver for RC522 card reader.");
MODULE_VERSION("1.0");
MODULE_LICENSE("GPL");