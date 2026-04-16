THEOS_DEVICE_IP =
THEOS_PACKAGE_DIR_NAME = debs
TARGET = iphone:clang:latest:14.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rbxtunnel
rbxtunnel_FILES = Tweak.xm
# Remove fishhook from files list
rbxtunnel_CFLAGS = -fobjc-arc -O2

include $(THEOS)/makefiles/tweak.mk
