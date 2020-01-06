#SPDX-License-Identifier: ISC

#ccflags-y += -DDEBUG -Werror -Wall

obj-$(CONFIG_MT7663E) += mt7663e.o
obj-$(CONFIG_MT7663U) += mt7663u.o
obj-$(CONFIG_MT7663_COMMON) += mt7663-common.o

mt7663-common-y := init.o dma.o eeprom.o main.o mcu.o mac.o debugfs.o

mt7663e-y := pci.o soc.o mmio.o pci_init.o pci_mcu.o pci_mac.o
mt7663u-y := usb.o usb_mcu.o usb_core.o usb_init.o usb_mac.o
