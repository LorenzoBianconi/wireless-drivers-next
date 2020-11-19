#SPDX-License-Identifier: ISC

ccflags-y := -Werror
obj-$(CONFIG_MT7921E) += mt7921e.o

mt7921e-y := pci.o init.o dma.o eeprom.o main.o mcu.o mac.o \
	     debugfs.o

mt7921e-$(CONFIG_NL80211_TESTMODE) += testmode.o
