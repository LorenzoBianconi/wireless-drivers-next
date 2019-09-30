#SPDX-License-Identifier: ISC

ccflags-y += -DDEBUG -Werror -Wall

obj-$(CONFIG_MT7629) += mt7629.o
obj-$(CONFIG_MT7663E) += mt7663e.o
obj-$(CONFIG_MT7663U) += mt7663u.o
obj-$(CONFIG_CONNAC_COMMON) += connac-common.o

connac-common-y := init.o dma.o eeprom.o main.o mcu.o mac.o debugfs.o

mt7629-y := soc.o
mt7663e-y := pci.o
mt7663u-y := usb.o
