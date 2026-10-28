# For every pcap: export flows via ipfixprobe and via tshark, then compare both.
# See README.md.
#
#   make -j$(nproc) check                         # regression pcaps, fails on any failed test
#   make -j$(nproc) compare PCAP_DIR=/path/pcaps  # any pcaps, results only
#   make summary                                  # print results of the last run
#   make check-tools
#   make clean
#
# PCAP_DIR must not contain spaces or ":" (make limitation).
SHELL       := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
# Keep the parquet files; make would otherwise delete them as intermediates.
.SECONDARY:

PCAP_DIR     ?= pcaps
OUT_DIR      ?= ./processed_data
RESULT_DIR   ?= ./results
SUDO         ?= sudo
IPFIXPROBE   ?= ipfixprobe
# Plugin directory for an ipfixprobe from a build tree (<build>/src/plugins).
PLUGIN_DIR   ?=
TSHARK       ?= tshark
FLOWPIPELINE ?= flowpipeline
PYTHON       ?= python3

PCAP_DIR   := $(patsubst %/,%,$(PCAP_DIR))
PCAPS      := $(shell find $(PCAP_DIR) -name '*.pcap')
IPFIX_OUT  := $(patsubst $(PCAP_DIR)/%.pcap,$(OUT_DIR)/ipfixprobe/%.parquet,$(PCAPS))
TSHARK_OUT := $(patsubst $(PCAP_DIR)/%.pcap,$(OUT_DIR)/tshark/%.parquet,$(PCAPS))
RESULT_OUT := $(patsubst $(PCAP_DIR)/%.pcap,$(RESULT_DIR)/%.json,$(PCAPS))

$(info $(words $(PCAPS)) pcaps in $(PCAP_DIR))

.PHONY: all compare check summary clean sudo-cache check-tools

all: $(IPFIX_OUT) $(TSHARK_OUT)

compare: $(RESULT_OUT)

# -k: one broken pcap must not hide the results of the others.
check:
	$(MAKE) -k compare || true
	$(PYTHON) summarize.py --strict $(PCAP_DIR) $(RESULT_DIR)

summary:
	@$(PYTHON) summarize.py $(PCAP_DIR) $(RESULT_DIR)

check-tools:
	@for t in $(IPFIXPROBE) tcpdump $(TSHARK) $(FLOWPIPELINE) $(PYTHON); do \
		command -v $$t > /dev/null || { echo "missing: $$t"; exit 1; }; \
	done
	@# -T '?' always exits with 1 after listing the formats.
	@{ $(TSHARK) -T '?' 2>&1 || true; } | grep -q parquet || { echo "tshark lacks parquet support"; exit 1; }
	@$(PYTHON) -c 'import polars' || { echo "missing python module: polars"; exit 1; }

# Ask for the sudo password once; otherwise parallel jobs fight over the prompt.
sudo-cache:
	@$(if $(SUDO),$(SUDO) -v,true)

# sudo resets the environment, so the ipfixprobe settings are passed explicitly.
$(OUT_DIR)/ipfixprobe/%.parquet: $(PCAP_DIR)/%.pcap | sudo-cache
	@mkdir -p $(dir $@)
	$(SUDO) env IPFIXPROBE=$(IPFIXPROBE) PLUGIN_DIR=$(PLUGIN_DIR) ./pipeline.sh "$<" \
		| $(FLOWPIPELINE) -c config.yml > "$@" \
		|| { echo "$<" >> $(OUT_DIR)/pipeline_failed.log; exit 1; }
	@[ -s "$@" ] || { echo "$<" >> $(OUT_DIR)/pipeline_failed.log; echo "error: empty output for $<"; exit 1; }

$(OUT_DIR)/tshark/%.parquet: $(PCAP_DIR)/%.pcap
	@mkdir -p $(dir $@)
	TSHARK=$(TSHARK) ./tshark-script.sh "$<" "$@"

$(RESULT_DIR)/%.json: $(OUT_DIR)/ipfixprobe/%.parquet $(OUT_DIR)/tshark/%.parquet $(PCAP_DIR)/%.pcap
	@mkdir -p $(dir $@)
	$(PYTHON) compare_flows.py \
		--tshark-file "$(OUT_DIR)/tshark/$*.parquet" \
		--pipeline-file "$(OUT_DIR)/ipfixprobe/$*.parquet" \
		--pcap "$(PCAP_DIR)/$*.pcap" \
		--out "$@"

clean:
	rm -rf $(OUT_DIR) $(RESULT_DIR)
