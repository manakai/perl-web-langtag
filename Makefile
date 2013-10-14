# -*- Makefile -*-

all:

update: update-registry
clean: clean-registry

WGET = wget
GIT = git
PERL = ./perl

dataautoupdate: clean deps update
	$(GIT) add lib/Web/LangTag/_List.pm lib/Web/LangTag/_ListFull.pm

## ------ Setup ------

deps: git-submodules pmbp-install

git-submodules:
	$(GIT) submodule update --init

local/bin/pmbp.pl:
	mkdir -p local/bin
	$(WGET) -O $@ https://raw.github.com/wakaba/perl-setupenv/master/bin/pmbp.pl
pmbp-upgrade: local/bin/pmbp.pl
	perl local/bin/pmbp.pl --update-pmbp-pl
pmbp-update: git-submodules pmbp-upgrade
	perl local/bin/pmbp.pl --update
pmbp-install: pmbp-upgrade
	perl local/bin/pmbp.pl --install \
            --create-perl-command-shortcut perl \
            --create-perl-command-shortcut prove

## ------ Language tag registry ------

update-registry: lib/Web/LangTag/_List.pm lib/Web/LangTag/_ListFull.pm
clean-registry:
	rm -f local/langtags.json

local/langtags.json:
	mkdir -p local
	$(WGET) -O $@ https://raw.github.com/manakai/data-web-defs/master/data/langtags.json
lib/Web/LangTag/_List.pm: local/langtags.json bin/generate-list-module.pl
	$(PERL) bin/generate-list-module.pl $< > $@
lib/Web/LangTag/_ListFull.pm: local/langtags.json bin/generate-list-module.pl
	FULL=1 $(PERL) bin/generate-list-module.pl $< > $@

## ------ Tests ------

PROVE = ./prove

test: test-deps test-main

test-deps: deps

test-main:
	$(PROVE) t/*.t