#SPDX-License-Identifier: ISC

obj-$(CONFIG_MT7615E) += mt7615e.o
obj-$(CONFIG_MT7663U) += mt7663u.o
obj-$(CONFIG_MT7615_COMMON) += mt7615-common.o

mt7615-common-y := mcu.o mac.o main.o init.o eeprom.o

mt7615e-y := pci.o pci_init.o dma.o pci_eeprom.o pci_main.o \
	     pci_mac.o debugfs.o

mt7663u-y := usb.o usb_core.o usb_init.o usb_mac.o usb_mcu.o
