TARGET       = v0rtex
PACKAGE      = net.siguza.v0rtex
VERSION      = 1.0.0
BIN          = bin
SRC          = src
RES          = res
APP          = $(BIN)/Payload/$(TARGET).app
PNGS        := $(wildcard $(RES)/*.png)
FILES       := $(TARGET) Info.plist $(PNGS:$(RES)/%=%)
IGCC        ?= xcrun -sdk iphoneos gcc
ARCH        ?= -arch armv7 -arch arm64
IGCC_FLAGS  ?= -Wall -O3 -fmodules -framework IOKit $(CFLAGS)
STRIP       ?= xcrun -sdk iphoneos strip

.PHONY: all clean

all: $(TARGET).ipa

$(TARGET).ipa: $(addprefix $(APP)/, $(FILES))
	cd $(BIN) && zip -x .DS_Store -qr9 ../$@ Payload

$(APP)/$(TARGET): $(SRC)/*.m | $(APP)
	$(IGCC) $(ARCH) -o $@ $(IGCC_FLAGS) $^
	$(STRIP) $@

$(APP)/Info.plist: $(RES)/Info.plist | $(APP)
	sed 's/$$(TARGET)/$(TARGET)/g;s/$$(PACKAGE)/$(PACKAGE)/g;s/$$(VERSION)/$(VERSION)/g' $(RES)/Info.plist > $@

$(APP)/%.png: $(RES)/$(@F) | $(APP)
	cp $(RES)/$(@F) $@

$(APP):
	mkdir -p $@

clean:
	rm -rf $(BIN) $(TARGET).ipa
