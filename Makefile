THEOS_DEVICE_IP =
THEOS_PACKAGE_DIR_NAME = debs
TARGET = iphone:clang:16.5:14.0  # SDK 16.5, min iOS 14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rbxtunnel
rbxtunnel_FILES = Tweak.xm
rbxtunnel_CFLAGS = -fobjc-arc -O2

include $(THEOS)/makefiles/tweak.mk
