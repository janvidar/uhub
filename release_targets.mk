autotest.c: $(autotest_SOURCES)
	$(shell exotic --standalone $(autotest_SOURCES) > $@)

ifeq ($(RELEASE),YES)

%.tar.bz2: %.tar
	@bzip2 -c -9 $^ > $@

%.tar.gz: %.tar
	@gzip -c -9 $^ > $@

ChangeLog-$(VERSION)-$(REVISION): ChangeLog
	@cp $^ $@

changelog: ChangeLog-$(VERSION)-$(REVISION)

$(PACKAGE_SRC).tar $(PACKAGE_SRC).zip: autotest.c
	@if [ -d $(PACKAGE) ]; then rm -Rf $(PACKAGE); fi
	@svn export . $(PACKAGE) > /dev/null
	@rm -f $(PACKAGE)/release_*.mk
	@grep -v \\-include $(PACKAGE)/GNUmakefile > $(PACKAGE)/GNUmakefile2
	@mv $(PACKAGE)/GNUmakefile2 $(PACKAGE)/GNUmakefile
	@mv $< $(PACKAGE)
	@tar cf $(PACKAGE_SRC).tar $(PACKAGE)
	@zip -r $(PACKAGE_SRC).zip $(PACKAGE)
	@rm -Rf $(PACKAGE)

$(PACKAGE_BIN).tar: clean $(uhub_BINARY)
	@if [ -d $(PACKAGE) ]; then rm -Rf $(PACKAGE); fi
	@svn export . $(PACKAGE) > /dev/null
	@rm -Rf $(PACKAGE)/src $(PACKAGE)/autotest $(PACKAGE)/*akefile $(PACKAGE)/$(LIBUHUB) $(PACKAGE)/release_*.mk $(PACKAGE)/version.h
	@cp $(uhub_BINARY) $(PACKAGE)
	@tar cf $@ $(PACKAGE)
	@rm -Rf $(PACKAGE)

$(PACKAGE_BIN).zip: clean $(uhub_BINARY)
	@if [ -d $(PACKAGE) ]; then rm -Rf $(PACKAGE); fi
	@svn export . $(PACKAGE) > /dev/null
	@rm -Rf $(PACKAGE)/src $(PACKAGE)/autotest $(PACKAGE)/*akefile $(PACKAGE)/$(LIBUHUB) $(PACKAGE)/release_*.mk $(PACKAGE)/version.h
	@cp $(uhub_BINARY) $(PACKAGE)
	@zip -r $@ $(PACKAGE)
	@rm -Rf $(PACKAGE)

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
	@scp -q $(PACKAGE_SRC).tar.gz $(PACKAGE_SRC).tar.bz2 $(PACKAGE_BIN).tar.gz $(PACKAGE_BIN).tar.bz2 ChangeLog-$(VERSION)-$(REVISION) $(URL_PUBLISH)

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

else


endif

