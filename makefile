TAGS = yara_static
LDFLAGS = '-extldflags=-static'

YARA_VERSION = 4.5.0
BUILD_DIR ?= yara-build
SRC = $(BUILD_DIR)/yara-$(YARA_VERSION)
YARA_BIN = $(BUILD_DIR)/bin/yara
PKG_CONFIG_PATH = $(abspath $(BUILD_DIR))/lib/pkgconfig

help:
	@grep -E '^[a-zA-Z0-9\.%]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## install necessary deps: automake libtool gcc pkg-config
	apt-get update; apt-get install -qqy automake libtool gcc pkg-config

ito: | $(YARA_BIN) ## build it-o
	PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) \
	CGO_ENABLED=1 \
	go build -tags $(TAGS) -ldflags $(LDFLAGS) -o $@

dev: ## attach to or create a desktop dev container with vscode
	(docker dev start ito && sleep 2 && docker dev open ito) \
		|| docker dev create --open --base-image "golang:1.20" --name ito $$PWD

clean: ## deletes downloaded src and yara deps
	rm -rf $(BUILD_DIR) ito

yara: $(YARA_BIN) ## only build yara dependencies
$(YARA_BIN): | $(BUILD_DIR)/v$(YARA_VERSION).tar.gz
	cd $(SRC) && \
		./bootstrap.sh && \
		./configure --disable-shared --prefix=$(abspath $(BUILD_DIR))
	$(MAKE) -C $(SRC) install

$(BUILD_DIR)/v$(YARA_VERSION).tar.gz:
	mkdir -p $(BUILD_DIR)
	wget --no-verbose -O $@ "https://github.com/VirusTotal/yara/archive/$(@F)"
	tar xzf $@ -C $(BUILD_DIR)


.PHONY: clean yara deps help
