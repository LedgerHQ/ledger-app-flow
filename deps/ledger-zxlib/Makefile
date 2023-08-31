#*******************************************************************************
#*   (c) 2019 Zondax GmbH
#*
#*  Licensed under the Apache License, Version 2.0 (the "License");
#*  you may not use this file except in compliance with the License.
#*  You may obtain a copy of the License at
#*
#*      http://www.apache.org/licenses/LICENSE-2.0
#*
#*  Unless required by applicable law or agreed to in writing, software
#*  distributed under the License is distributed on an "AS IS" BASIS,
#*  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#*  See the License for the specific language governing permissions and
#*  limitations under the License.
#********************************************************************************

ifeq ($(REPO_DIR),)
REPO_DIR=$(CURDIR)/../..
endif

TESTS_SPECULOS_DIR?=$(REPO_DIR)/tests_speculos
TESTS_JS_PACKAGE?="@onflow/ledger"
TESTS_JS_DIR?=$(REPO_DIR)/js
TESTS_GENERATE_DIR?=$(REPO_DIR)/tests/generate-transaction-tests
MAKE_NVM_SH_PATH?=~

ifeq ($(TARGET_NAME), NANO_S)
    TEST_DEVICE=nanos
endif
ifeq ($(TARGET_NAME), NANO_X)
    TEST_DEVICE=nanox
endif
ifeq ($(TARGET_NAME), NANO_SP)
    TEST_DEVICE=nanosp
endif

$(info TARGET_NAME           : $(TARGET_NAME))
$(info TESTS_SPECULOS_DIR    : $(TESTS_SPECULOS_DIR))
$(info TESTS_JS_PACKAGE      : $(TESTS_JS_PACKAGE))
$(info TESTS_JS_DIR          : $(TESTS_JS_DIR))
$(info TESTS_GENERATE_DIR    : $(TESTS_GENERATE_DIR))
$(info MAKE_NVM_SH_PATH      : $(MAKE_NVM_SH_PATH))

all: speculos_pull_container

########################## CHECK Section ###############################

.PHONY: check_todo check_fixme check_python deps
check_todo:
	@git ls-files 2>&1 | xargs egrep -i "\b[t]odo:" 2> /dev/null || true

check_fixme:
	@git ls-files 2>&1 | xargs egrep -i "\b[f]ixme:" 2> /dev/null || true

check_python:
	@python -c 'import sys; sys.exit(3-sys.version_info.major)' || (echo "The python command does not point to Python 3"; exit 1)

deps: check_python
	@echo "Install dependencies"
	$(CURDIR)/scripts/install_deps.sh

########################## SPECULOS Section ###############################
.PHONY: speculos_install_js_link
speculos_install_js_link:
	$(call run_announce,$@)
	# First unlink everything
	@# todo: workaround to avoid this log output? 'error No registered package found called "@onflow/ledger"'
	cd $(TESTS_JS_DIR) && yarn unlink || true
	cd $(TESTS_SPECULOS_DIR) && yarn unlink $(TESTS_JS_PACKAGE) || true
	# Now build and link
	cd $(TESTS_JS_DIR) && yarn install && yarn build && yarn link || true
	cd $(TESTS_SPECULOS_DIR) && yarn link $(TESTS_JS_PACKAGE) && yarn install || true
	@echo
	# List linked packages
	@echo
	@cd $(TESTS_SPECULOS_DIR) && ( ls -l node_modules ; ls -l node_modules/@* ) | grep ^l || true
	@echo

.PHONY: speculos_pull_container
speculos_pull_container:
	docker pull ghcr.io/ledgerhq/speculos:latest
	docker image tag ghcr.io/ledgerhq/speculos:latest speculos

.PHONY: speculos_install
speculos_install: speculos_install_js_link speculos_pull_container
	$(call run_announce,$@)
	# check for nvm, node, npm, and yarn
	@. $(MAKE_NVM_SH_PATH)/.nvm/nvm.sh ; nvm --version 2>&1 | perl -lane '$$nvm=$$_; chomp $$nvm; printf qq[# nvm --version: %s\n], $$nvm; if($$nvm!~m~^\d+\.\d+\.\d+$$~){ die qq[ERROR: nvm not installed? Please install, e.g. MacOS/Ubuntu: curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash ; export NVM_DIR="$$HOME/.nvm" ; [ -s "$$NVM_DIR/nvm.sh" ] && \. "$$NVM_DIR/nvm.sh" ; [ -s "$$NVM_DIR/bash_completion" ] && \. "$$NVM_DIR/bash_completion" # see https://github.com/nvm-sh/nvm#installing-and-updating\n]; }'
	@node --version 2>&1 | perl -lane '$$node=$$_; chomp $$node; printf qq[# node --version: %s\n], $$node; if($$node!~m~^v16\.10\.0$$~){ die qq[ERROR: desired node version not installed? Please install, e.g. MacOS/Ubuntu: nvm install 16.10.0 ; nvm use 16.10.0]; }'
	@perl -e '$$yarn=`which yarn`; chomp $$yarn; printf qq[# which yarn: %s\n], $$yarn; if($$yarn=~m~^\s*$$~){ die qq[ERROR: yarn not installed? Please install, e.g. Ubuntu: sudo npm install --global yarn Linux: brew install yarn\n]; }'
	# delete node_modules
	cd $(TESTS_SPECULOS_DIR) && rm -rf node_modules
	# run yarn install
	@cd $(TESTS_SPECULOS_DIR) && yarn install

.PHONY: speculos_port_5001_start
speculos_port_5001_start: speculos_pull_container
	$(call run_announce,$@)
	$(call start_speculos_container,5001,40001,41001,/bin)

.PHONY: speculos_port_5002_start
speculos_port_5002_start: speculos_pull_container
	$(call run_announce,$@)
	$(call start_speculos_container,5002,40002,41002,/bin)

.PHONY: speculos_port_5003_start
speculos_port_5003_start: speculos_pull_container
	$(call run_announce,$@)
	$(call start_speculos_container,5003,40003,41003,/tests_speculos/backward_compatibility_test_biniaries/0-9-12/)

.PHONY: speculos_port_5001_stop
speculos_port_5001_stop:
	$(call run_announce,$@)
	$(call stop_speculos_container,5001)

.PHONY: speculos_port_5002_stop
speculos_port_5002_stop:
	$(call run_announce,$@)
	$(call stop_speculos_container,5002)

.PHONY: speculos_port_5003_stop
speculos_port_5003_stop:
	$(call run_announce,$@)
	$(call stop_speculos_container,5003)

########################## TEST Section ###############################

.PHONY: generate_test_vectors
generate_test_vectors:
	cd $(TESTS_GENERATE_DIR) && yarn run generate

# Note: This error did occur once: docker: Error response from daemon: driver failed programming external connectivity on endpoint speculos-port-5002 (082ea92d039f260880bc264a2f6086e14c42d698f24ff5acbba422baa9c60b29): Error starting userland proxy: listen tcp 0.0.0.0:41002: bind: address already in use.
# Note: Since we do not need to use the VNC for the tests, then remove this option and hope the error never shows up again: --vnc-port $(3)
define start_speculos_container
	docker run --detach --name speculos-port-$(1) --rm -it -v $(REPO_DIR)$(4):/speculos/bin --publish $(1):$(1) --publish $(2):$(2) --publish $(3):$(3) speculos --model $(TEST_DEVICE) --seed "equip will roof matter pink blind book anxiety banner elbow sun young" --display headless --apdu-port $(2) --api-port $(1) ./bin/app.elf ; rm -f $(TESTS_SPECULOS_DIR)/speculos-port-$(1).log ; docker logs --follow speculos-port-$(1) 2>&1 | tee -a $(TESTS_SPECULOS_DIR)/speculos-port-$(1).log > /dev/null 2>&1 &
	@perl -e 'use Time::HiRes; $$t1=Time::HiRes::time(); while(1){ $$o=`cat $(TESTS_SPECULOS_DIR)/speculos-port-$(1).log`; if($$o =~ m~Running on .*\:$(1)~s){ printf qq[# detected -- via log -- speculos listening after %f seconds; spy on emulated device via http://localhost:$(1)/\n], Time::HiRes::time() - $$t1; exit; } Time::HiRes::sleep(0.01); };'
endef

define stop_speculos_container
	# make: todo: using --time 0 because this stops the docker container faster; but it still takes ~ 2.4 seconds... how to stop faster?
	docker stop --time 0 speculos-port-$(1)
endef

define run_announce
	@perl -e 'use Time::HiRes; use POSIX; $$ts = sprintf qq[%f], Time::HiRes::time(); ($$f) = $$ts =~ m~(\....)~; printf qq[%s%s %s make: %s\n], POSIX::strftime("%H:%M:%S", gmtime), $$f, q[-] x 126, $$ARGV[0];' "$(1)"
endef

define run_nodejs_test
	@cd $(TESTS_SPECULOS_DIR) \
	&& { { { \
          TEST_SPECULOS_API_PORT=$(1) TEST_SPECULOS_APDU_PORT=$(2) TEST_DEVICE=$(TEST_DEVICE) node $(3) 2>&1; echo $$? >&3; \
        } | tee -a speculos-port-$(1).log >&4; } 3>&1 | { read xs; exit $$xs; } } 4>&1
endef


.PHONY: speculos_port_5001_test_internal
speculos_port_5001_test_internal:
	$(call run_announce,$@)
	$(call run_nodejs_test,5001,40001,test-basic-app-version.js)
	$(call run_nodejs_test,5001,40001,test-basic-slot-status-bad-net.js)
	$(call run_nodejs_test,5001,40001,test-basic-slot-status-full.js)
	$(call run_nodejs_test,5001,40001,test-basic-sign-basic-invalid.js)
	$(call run_nodejs_test,5001,40001,test-basic-get-address.js)
	$(call run_nodejs_test,5001,40001,test-basic-show-address-secp256k1.js)
	$(call run_nodejs_test,5001,40001,test-basic-show-address-secp256r1.js)
	$(call run_nodejs_test,5001,40001,test-basic-show-address-expert.js)
	$(call run_nodejs_test,5001,40001,test-menu.js)
	@echo "# ALL TESTS COMPLETED!" | tee -a $(TESTS_SPECULOS_DIR)/speculos-port-5001.log

.PHONY: speculos_port_5002_test_internal
speculos_port_5002_test_internal:
	$(call run_announce,$@)
	$(call run_nodejs_test,5002,40002,test-slot-transaction-interaction.js)
	$(call run_nodejs_test,5002,40002,test-transaction-expert-mode.js)
	$(call run_nodejs_test,5002,40002,test-transactions.js)
	@echo "# ALL TESTS COMPLETED!" | tee -a $(TESTS_SPECULOS_DIR)/speculos-port-5002.log

.PHONY: speculos_port_5003_test_internal
speculos_port_5003_test_internal:
	$(call run_announce,$@)
	$(call run_nodejs_test,5003,40003,test-backward-compatibility-0-9-12.js)
	@echo "# ALL TESTS COMPLETED!" | tee -a $(TESTS_SPECULOS_DIR)/speculos-port-5003.log

.PHONY: speculos_port_5001_test
speculos_port_5001_test:
	$(call run_announce,$@)
	$(MAKE) --no-print-directory speculos_port_5001_start && ($(MAKE) --no-print-directory speculos_port_5001_test_internal; ret=$$?;$(MAKE) --no-print-directory speculos_port_5001_stop;$(call run_announce,note: logs: cat $(TESTS_SPECULOS_DIR)/speculos-port-5001.log);cat $(TESTS_SPECULOS_DIR)/speculos-port-5001.log; exit $$ret)

.PHONY: speculos_port_5002_test
speculos_port_5002_test:
	$(call run_announce,$@)
	$(MAKE) --no-print-directory speculos_port_5002_start && ($(MAKE) --no-print-directory speculos_port_5002_test_internal; ret=$$?;$(MAKE) --no-print-directory speculos_port_5002_stop;$(call run_announce,note: logs: cat $(TESTS_SPECULOS_DIR)/speculos-port-5002.log);cat $(TESTS_SPECULOS_DIR)/speculos-port-5002.log; exit $$ret)

.PHONY: speculos_port_5003_test
speculos_port_5003_test:
	$(call run_announce,$@)
	$(MAKE) --no-print-directory speculos_port_5003_start && ($(MAKE) --no-print-directory speculos_port_5003_test_internal; ret=$$?;$(MAKE) --no-print-directory speculos_port_5003_stop;$(call run_announce,note: logs: cat $(TESTS_SPECULOS_DIR)/speculos-port-5003.log);cat $(TESTS_SPECULOS_DIR)/speculos-port-5003.log; exit $$ret)

.PHONY: cpp_test
cpp_test:
	mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make
	cd build && GTEST_COLOR=1 ASAN_OPTIONS=detect_leaks=0 ctest -VV
