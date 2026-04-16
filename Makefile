THEOS_DEVICE_IP = 192.168.1.100
ARCHS = arm64
TARGET = iphone:clang:14.0:14.0

INSTALL_TARGET_PROCESSES = Roblox

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = rbxtunnel

rbxtunnel_FILES = Tweak.xm
rbxtunnel_CFLAGS = -fobjc-arc -O2 -Wno-unused-function
rbxtunnel_LDFLAGS = -Wl,-segalign,4000  # Critical for iOS 9+ compatibility [^3^]

include $(THEOS_MAKE_PATH)/tweak.mk

after-install::
	install.exec "killall -9 Roblox"
