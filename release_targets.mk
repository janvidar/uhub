autotest.c: $(autotest_SOURCES)
	$(shell exotic --standalone $(autotest_SOURCES) > $@)

ifeq ($(RELEASE),YES)

%.tar.bz2: %.tar
	@bzip2 -c -9 $^ > $@

%.tar.gz: %.tar
	@gzip -c -9 $^ > $@

ChangeLog-$(VERSION): ChangeLog
	@cp $^ $@

changelog: ChangeLog-$(VERSION)

define gitexport
	@if [ -d $(PACKAGE) ]; then rm -Rf $(PACKAGE); fi
	@git archive --format=tar --prefix=$(PACKAGE)/ $(REVISION) | tar x
endef

define cleanexport
	@if [ -d $(PACKAGE) ]; then rm -Rf $(PACKAGE); fi
endef

package:
	$(gitexport)
	@rm -f $(PACKAGE)/release_*.mk
	@grep -v \\-include $(PACKAGE)/GNUmakefile > $(PACKAGE)/GNUmakefile2
	@mv $(PACKAGE)/GNUmakefile2 $(PACKAGE)/GNUmakefile
	@$(shell exotic --standalone $(autotest_SOURCES) > $(PACKAGE)/autotest.c )

package-bin:
	$(gitexport)
	@rm -Rf $(PACKAGE)/src
	@rm -Rf $(PACKAGE)/autotest
	@rm -f $(PACKAGE)/autotest.c
	@rm -f $(PACKAGE)/*akefile
	@rm -f $(PACKAGE)/release_*.mk
	@rm -f $(PACKAGE)/version.h
	@rm -f $(PACKAGE)/doc/architecture.txt
	@rm -f $(PACKAGE)/doc/Doxyfile
	@rm -f $(PACKAGE)/doc/uhub.dot
	@rm -f $(PACKAGE)/doc/extensions.txt

package-bin-build: package-bin clean $(uhub_BINARY)
	@cp $(uhub_BINARY) $(PACKAGE)

$(PACKAGE_SRC).tar: package
	@tar cf $(PACKAGE_SRC).tar $(PACKAGE)

$(PACKAGE_SRC).zip: package
	@zip -q -9 -r $(PACKAGE_SRC).zip $(PACKAGE)	

$(PACKAGE_BIN).tar: package-bin-build
	@tar cf $(PACKAGE_BIN).tar $(PACKAGE)

$(PACKAGE_BIN).zip: package-bin-build
	@zip -q -9 -r $(PACKAGE_BIN).zip

$(PACKAGE_SRC).tar.gz: $(PACKAGE_SRC).tar

$(PACKAGE_SRC).tar.bz2: $(PACKAGE_SRC).tar

$(PACKAGE_BIN).tar.gz: $(PACKAGE_BIN).tar

$(PACKAGE_BIN).tar.bz2: $(PACKAGE_BIN).tar

snapshot: tarballs
	@mv $(PACKAGE_SRC).tar.gz uhub-snapshot-$(SNAPSHOT).tar.gz
	@rm $(PACKAGE_SRC).tar.bz2

publish-snapshot: snapshot
	@scp -q uhub-snapshot-$(SNAPSHOT).tar.gz $(URL_SNAPSHOT)

publish: release
	@scp -q $(PACKAGE_SRC).tar.gz $(PACKAGE_SRC).tar.bz2 $(PACKAGE_BIN).tar.gz $(PACKAGE_BIN).tar.bz2 ChangeLog-$(VERSION) $(URL_PUBLISH)

tarballs: $(PACKAGE_SRC).tar.gz $(PACKAGE_SRC).tar.bz2 $(PACKAGE_SRC).zip
	@rm $(PACKAGE_SRC).tar

ifeq ($(WINDOWS), YES)
binaries: $(PACKAGE_BIN).tar.gz $(PACKAGE_BIN).tar.bz2 $(PACKAGE_BIN).zip
	@rm $(PACKAGE_BIN).tar

else
binaries: $(PACKAGE_BIN).tar.gz $(PACKAGE_BIN).tar.bz2
	@rm $(PACKAGE_BIN).tar
endif

release: binaries tarballs changelog
	$(cleanexport)
else


endif

