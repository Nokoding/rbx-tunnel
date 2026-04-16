THEOS_DEVICE_IP = 192.168.1.100
ARCHS = arm64
TARGET = iphone:clang:14.0:14.0

INSTALL_TARGET_PROCESSES = Roblox

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rbxtunnel

rbxtunnel_FILES = Tweak.xm
rbxtunnel_CFLAGS = -fobjc-arc -Wall -Werror -O2
rbxtunnel_LDFLAGS = -framework Foundation
rbxtunnel_LIBRARIES = 

include $(THEOS_MAKE_PATH)/tweak.mk
