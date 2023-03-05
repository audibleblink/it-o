TAGS = yara_static
LDFLAGS = '-extldflags=-static'

YARA_VERSION = 4.2.1
BUILD_DIR = yara-build
SRC = ${BUILD_DIR}/yara-${YARA_VERSION}
YARA_BIN = ${BUILD_DIR}/bin/yara
PKG_CONFIG_PATH = ${BUILD_DIR}/lib/pkgconfig

help:
	@grep -E '^[a-zA-Z0-9\.%]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'

deps: ## install necessary deps: automake libtool make gcc pkg-config
	sudo apt install automake libtool make gcc pkg-config

ito: $(YARA_BIN) ## build it-o
	CGO_ENABLED=1 \
	go build -tags ${TAGS} -ldflags ${LDFLAGS} -o $@

clean: ## deletes downloaded src and yara deps
	rm -rf ${BUILD_DIR} ito

yara: $(YARA_BIN) ## only build yara dependencies
$(YARA_BIN): $(BUILD_DIR)/v${YARA_VERSION}.tar.gz
	cd ${SRC} && \
		./bootstrap.sh && \
		./configure --disable-shared --prefix=$(abspath ${BUILD_DIR})
	$(MAKE) -C ${SRC} install

$(BUILD_DIR)/v${YARA_VERSION}.tar.gz: $(BUILD_DIR)
	wget --no-verbose -O $@ "https://github.com/VirusTotal/yara/archive/$(@F)"
	tar xzf $@ -C $<

$(BUILD_DIR):
	mkdir -p $@

.PHONY: clean yara deps help
