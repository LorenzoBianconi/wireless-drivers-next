#SPDX-License-Identifier: ISC

obj-$(CONFIG_MT7615E) += mt7615e.o
obj-$(CONFIG_MT7615_COMMON) += mt7615-common.o

mt7615-common-y := mcu.o mac.o main.o

mt7615e-y := pci.o init.o dma.o eeprom.o pci_main.o pci_mac.o \
	     debugfs.o
