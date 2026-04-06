#!/usr/bin/make
# This is the sophomorix Makefile
# for Debian packaging (make DESTDIR=/root/sophomorix)
DESTDIR=

# Installing from this Makefile
#====================================
# if you use this Makefile to install sophomorix (instead of 
# installing the debian-Package) you will miss:
#   1. html-documentation
#   2. manpages
# This is because debian has scripts to install 1. and 2. VERY easily
# see debian/rules -> dh_installman, dh-installdocs



# Debian
#====================================

# Homes
#HOME=$(DESTDIR)/home

# Developement
#USERROOT=$(DESTDIR)/root

# Data
LIBDIR=$(DESTDIR)/var/lib/sophomorix

# Cache
#CACHEDIR=$(DESTDIR)/var/cache/sophomorix

# Logs
LOGDIR=$(DESTDIR)/var/log/sophomorix

# Perl modules
PERLMOD=$(DESTDIR)/usr/share/perl5/Sophomorix

# Python modules
PYTHONMOD=$(DESTDIR)/usr/lib/python3/dist-packages/sophomorix

# Dokumentation
#DOCDEBDIR=$(DESTDIR)/usr/share/doc

# configs
CONF=$(DESTDIR)/etc/linuxmuster/sophomorix

# Schema
SCHEMA=$(DESTDIR)/usr/share/sophomorix/schema

# Developer configs
DEVELCONF=$(DESTDIR)/usr/share/sophomorix
DEVELBELVUECONF=$(DESTDIR)/usr/share/sophomorix-belwue

# Migration conf
DUMPCONF=$(DESTDIR)/usr/share/sophomorix-dump
VAMPIRECONF=$(DESTDIR)/usr/share/sophomorix-vampire

# Encoding-data
ENCODING=$(DESTDIR)/usr/share/sophomorix/encoding-data

# Language
LANGUAGE=$(DESTDIR)/usr/share/sophomorix/lang

# Latex
LATEX=$(DESTDIR)/usr/share/sophomorix/lang/latex

# Filter
FILTER=$(DESTDIR)/usr/share/sophomorix/filter

# startscripts-skel
STARTSCRIPTSSKEL=$(DESTDIR)/usr/share/sophomorix/devel/startscript-skel

# SAMBADEBCONFDIR für Debian 
#SAMBADEBCONFDIR=$(DESTDIR)/etc/samba

# SAMBA Debian 
#SAMBADIR=$(DESTDIR)/var/lib/samba
#SAMBAROOTPREEXEC=$(DESTDIR)/etc/linuxmuster/samba/root-preexec.d
#SAMBAROOTPOSTEXEC=$(DESTDIR)/etc/linuxmuster/samba/root-postexec.d

# Config-templates
#CTEMPDIR=$(DESTDIR)/usr/share/sophomorix/config-templates

# Testfiles
DEVELOPERDIR=$(DESTDIR)/usr/share/sophomorix-developer
TESTDATA=$(DESTDIR)/usr/share/sophomorix-developer/testdata
TESTFILES=$(DESTDIR)/usr/share/sophomorix-developer/testfiles
EXAMPLEFILES=$(DESTDIR)/usr/share/sophomorix-developer/examplefiles
TESTTEMPLATES=$(DESTDIR)/usr/share/sophomorix-developer/testtemplates


# sophomorix-virusscan
#VIRUSSCAN=$(DESTDIR)/usr/share/sophomorix-virusscan

# Tools
#TOOLS=$(DESTDIR)/root/sophomorix-developer


all: install-sophomorix-samba install-virusscan install-developer install-vampire install-dump install-belwue-mail

help:
	@echo ' '
	@echo 'Most common options of this Makefile:'
	@echo '-------------------------------------'
	@echo ' '
	@echo '   make help'
	@echo '      show this help'
	@echo ' '
	@echo '   make | make all'
	@echo '      make an installation of files to the local ubuntu bionic'
	@echo ' '
	@echo '   make install-virusscan'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make install-sophomorix-samba'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make install-developer'
	@echo '      create a debian package'
	@echo ' '
	@echo '   make deb'
	@echo '      create a debian package for ubuntu bionic'
	@echo ' '


deb:
	### Prepare to build an ubuntu bionic package
	@echo 'Did you do a dch -i ?'
	@sleep 2
	dpkg-buildpackage -tc -uc -us -sa -rfakeroot
	@echo ''
	@echo 'Do not forget to tag this version with: git tag V-x.y.z'
	@echo ''

#clean: clean-doc clean-debian
clean: clean-debian

clean-debian:
	rm -rf  debian/sophomorix4
#	rm -rf  debian/sophomorix4-virusscan


# sophomorix-samba
install-sophomorix-samba:
	### install-samba
# some dirs
	@install -d -m700 -oroot -groot $(LIBDIR)
	@install -d -m700 -oroot -groot $(LIBDIR)/tmp
	@install -d -m700 -oroot -groot $(LIBDIR)/lock
	@install -d -m700 -oroot -groot $(LIBDIR)/print-data
	@install -d -m700 -oroot -groot $(LIBDIR)/check-result
	@install -d -m700 -oroot -groot $(LOGDIR)
	@install -d -m700 -oroot -groot $(LOGDIR)/user
	@install -d -m700 -oroot -groot $(LOGDIR)/cron
# Install the perl scripts
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-samba/scripts/sophomorix-*[a-z1-9] $(DESTDIR)/usr/sbin
# Install the perl modules
	@install -d -m755 -oroot -groot $(PERLMOD)
	@install -oroot -groot --mode=0644 sophomorix-samba/modules/Sophomorix*[a-z1-9.]pm $(PERLMOD)
# Install the python modules
	@install -d -m755 -oroot -groot $(PYTHONMOD)
	@install -oroot -groot --mode=0644 sophomorix-samba/python/modules/*[a-z1-9.]py $(PYTHONMOD)
# Install the python scripts
	@install -oroot -groot --mode=0744 sophomorix-samba/python/scripts/sophomorix-*[a-z1-9] $(DESTDIR)/usr/sbin
# install schema
	@install -d -m755 -oroot -groot $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/1_sophomorix-attributes.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/2_sophomorix-classes.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/3_sophomorix-aux.ldif $(SCHEMA)/
	@install -oroot -groot --mode=0755 sophomorix-samba/schema/sophomorix_schema_add.sh $(SCHEMA)/
	@install -d -m755 -oroot -groot $(SCHEMA)/schema-updates
	@install -oroot -groot --mode=0644 sophomorix-samba/schema/schema-updates/sophomorix-schema-update-[0-9]*.ldif $(SCHEMA)/schema-updates
# installing configs for root
	@install -d -m755 -oroot -groot $(CONF)
# configs for developers
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/sophomorix-devel.conf $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/sophomorix.ini $(DEVELCONF)/devel
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/README.repdir $(DEVELCONF)/devel
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/master
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/master/school.conf.master $(DEVELCONF)/devel/master
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/master/sophomorix.conf.master $(DEVELCONF)/devel/master
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/master/group.default.conf.master $(DEVELCONF)/devel/master
# config templates
	@install -d -m755 -oroot -groot $(DEVELCONF)/config-templates
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/sophomorix.conf.template.ini $(DEVELCONF)/config-templates
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/school.conf.template.ini $(DEVELCONF)/config-templates
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/devices.csv.template $(DEVELCONF)/config-templates
#	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/WEBUI.template.ini $(DEVELCONF)/config-templates
#	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/ANOTHER_UI.template.ini $(DEVELCONF)/config-templates
	@install -oroot -groot --mode=0644 sophomorix-samba/config-template/test-ui-perm.ini $(DEVELCONF)/config-templates
# repdir files
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.linux $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.global $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.school $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.school_gpo $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.project $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.globaladministrator_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.schooladministrator_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.teacher_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.adminclass $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.staffclass $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.extraclass $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.student_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.parent_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.staff_home $(DEVELCONF)/devel/repdir
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/repdir/repdir.examuser_home $(DEVELCONF)/devel/repdir
# ntacls
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/ntacl
	@install -oroot -groot --mode=0644 sophomorix-samba/config-devel/ntacl/*ntacl.template $(DEVELCONF)/devel/ntacl
# gpo stuff
	@install -d -m755 -oroot -groot $(DEVELCONF)/devel/gpo
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school.ldif.template $(DEVELCONF)/devel/gpo
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/Printers.xml.template $(DEVELCONF)/devel/gpo
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/Printers.xml.template.pre $(DEVELCONF)/devel/gpo
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/Printers.xml.template.post $(DEVELCONF)/devel/gpo
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/GPT.INI $(DEVELCONF)/devel/gpo/school/GPT.INI
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/Machine/comment.cmtx $(DEVELCONF)/devel/gpo/school/Machine/comment.cmtx
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/Machine/Registry.pol $(DEVELCONF)/devel/gpo/school/Machine/Registry.pol
	@install -D -oroot -groot --mode=0644 "sophomorix-samba/config-devel/gpo/school/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf" "$(DEVELCONF)/devel/gpo/school/Machine/Microsoft/Windows NT/SecEdit/GptTmpl.inf"
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/Machine/Scripts/scripts.ini $(DEVELCONF)/devel/gpo/school/Machine/Scripts/scripts.ini 
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/Machine/Scripts/Startup/http_proxy_signing_ca.p12 $(DEVELCONF)/devel/gpo/school/Machine/Scripts/Startup/http_proxy_signing_ca.p12
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/User/Preferences/Drives/Drives.xml $(DEVELCONF)/devel/gpo/school/User/Preferences/Drives/Drives.xml 
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/User/Preferences/Printers/Printers.xml $(DEVELCONF)/devel/gpo/school/User/Preferences/Printers/Printers.xml 
	@install -D -oroot -groot --mode=0644 sophomorix-samba/config-devel/gpo/school/User/Scripts/scripts.ini $(DEVELCONF)/devel/gpo/school/User/Scripts/scripts.ini 
# language stuff
	@install -d -m755 -oroot -groot $(LANGUAGE)
#	@install -oroot -groot --mode=0644 sophomorix-samba/lang/sophomorix-lang.*[a-z] $(LANGUAGE)
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/errors.*[a-z] $(LANGUAGE)
# latex stuff
	@install -d -m755 -oroot -groot $(LATEX)
	@install -d -m755 -oroot -groot $(LATEX)/templates
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/latex/README.latextemplates $(LATEX)
	@install -oroot -groot --mode=0644 sophomorix-samba/lang/latex/templates/*[a-z0-9-]-template.tex $(LATEX)/templates
# Encoding-data
	@install -d -m755 -oroot -groot $(ENCODING)
	@install -oroot -groot --mode=0644 sophomorix-samba/encoding-data/*.txt $(ENCODING)
# filter scripts
	@install -d -m755 -oroot -groot $(FILTER)
	@install -oroot -groot --mode=0755 sophomorix-samba/filter/*.filter $(FILTER)
# startscripts
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/custom
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/custom/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/linux/logoff.sh $(STARTSCRIPTSSKEL)/custom/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/linux/logon.sh $(STARTSCRIPTSSKEL)/custom/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/linux/sysstart.sh $(STARTSCRIPTSSKEL)/custom/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/linux/sysstop.sh $(STARTSCRIPTSSKEL)/custom/linux
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/custom/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/windows/logoff.bat $(STARTSCRIPTSSKEL)/custom/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/windows/logon.bat $(STARTSCRIPTSSKEL)/custom/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/windows/sysstart.bat $(STARTSCRIPTSSKEL)/custom/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/custom/windows/sysstop.bat $(STARTSCRIPTSSKEL)/custom/windows
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/lmn
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/lmn/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/linux/logoff.sh $(STARTSCRIPTSSKEL)/lmn/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/linux/logon.sh $(STARTSCRIPTSSKEL)/lmn/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/linux/sysstart.sh $(STARTSCRIPTSSKEL)/lmn/linux
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/linux/sysstop.sh $(STARTSCRIPTSSKEL)/lmn/linux
	@install -d -m755 -oroot -groot $(STARTSCRIPTSSKEL)/lmn/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/windows/logoff.bat $(STARTSCRIPTSSKEL)/lmn/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/windows/logon.bat $(STARTSCRIPTSSKEL)/lmn/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/windows/sysstart.bat $(STARTSCRIPTSSKEL)/lmn/windows
	@install -oroot -groot --mode=0644 sophomorix-samba/startscripts-skel/lmn/windows/sysstop.bat $(STARTSCRIPTSSKEL)/lmn/windows


install-virusscan:
	### install-virusscan
#	@install -d -m755 -oroot -groot $(CONF)/virusscan
#	@install sophomorix-virusscan/config/sophomorix-virusscan.conf $(CONF)/virusscan
#	@install sophomorix-virusscan/config/sophomorix-virusscan-excludes.conf $(CONF)/virusscan
#	@install -d $(DESTDIR)/usr/sbin
#	@install -oroot -groot --mode=0744 sophomorix-virusscan/scripts/sophomorix-virusscan $(DESTDIR)/usr/sbin


#install-janitor:
#	### install-janitor
#	@install -d $(DESTDIR)/usr/sbin
#	@install -oroot -groot --mode=0744 sophomorix-base/scripts/sophomorix-janitor $(DESTDIR)/usr/sbin

install-vampire:
	### install-vampire
	@install -d -m755 -oroot -groot $(VAMPIRECONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/config-dump-vampire-common/migration-6-to-7.conf $(VAMPIRECONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/ldif/ldif-pwdload.ldif.template $(VAMPIRECONF)

	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-vampire/scripts/sophomorix-vampire $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-vampire/scripts/sophomorix-vampire-pwdconvert $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-vampire/scripts/sophomorix-vampire-example $(DESTDIR)/usr/sbin

install-dump:
	### install-dump
	@install -d -m755 -oroot -groot $(DUMPCONF)
	@install -oroot -groot --mode=0644 sophomorix-vampire/config-dump-vampire-common/migration-6-to-7.conf $(DUMPCONF)
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-dump/scripts/sophomorix-dump $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-dump/scripts/sophomorix-dump-postgres-views.sh $(DESTDIR)/usr/sbin

install-belwue-mail:
	### install-belwue-mail
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-belwue/scripts/sophomorix-belwue $(DESTDIR)/usr/sbin
	@install -d $(DEVELBELVUECONF)
	@install -d $(DEVELBELVUECONF)/config-templates
	@install -oroot -groot --mode=0644 sophomorix-belwue/config-template/belwue-mail.conf.template.ini $(DEVELBELVUECONF)/config-templates


install-developer:
	### install-developer
### installing test scripts
	@install -d $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-supertest $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-*[0-9] $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-workflow $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-workflow-schoolisolation $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-errorfiles $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-infoscripts $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-test-exammode $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/scripts/sophomorix-JSON-example $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/schema-tools/sophomorix-testtool-set-schema-version $(DESTDIR)/usr/sbin
	@install -oroot -groot --mode=0744 sophomorix-developer/test-tools/sophomorix-testtool-convert-to-focal $(DESTDIR)/usr/sbin
# copying perl developer modules
	@install -d -m755 -oroot -groot $(PERLMOD)
	@install -oroot -groot --mode=0644 sophomorix-developer/modules/SophomorixTest.pm $(PERLMOD)
# installing  examples
	@install -d $(DEVELOPERDIR)
# installing templates
	@install -d $(TESTTEMPLATES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testtemplates/*.ini.test $(TESTTEMPLATES)
# schema tols
	@install -d -m755 -oroot -groot $(DEVELOPERDIR)/schema-tools
	@install -oroot -groot --mode=0644 sophomorix-developer/schema-tools/sophomorix-schema-update-set-schema-version.ldif $(DEVELOPERDIR)/schema-tools

# installing  examplefiles
	@install -d $(EXAMPLEFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/examplefiles/students.csv.utf-8 $(EXAMPLEFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/examplefiles/students.csv.8859_1 $(EXAMPLEFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/examplefiles/students.csv.ascii $(EXAMPLEFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/examplefiles/students.csv.mixed $(EXAMPLEFILES)

# installing  testdata
	@install -d $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-02.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-03.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-01.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-02.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-03.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-03-01.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-03-02.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-01-01.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-01-02.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-03-01.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-03-02.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/testfile-01-03-03.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/blockfile.txt $(TESTFILES)
	@install -oroot -groot --mode=0644 sophomorix-developer/testfiles/blockfile2.txt $(TESTFILES)


# installing  testdata
	@install -d $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-firstname $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-lastname $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-birthdate $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-errors-class $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-30 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-40 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.add-exammode $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.update-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-30 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-40 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/sophomorix.kill-exammode $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/uni.students.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/uni.teachers.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-2 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-2 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-3 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-4 $(TESTDATA)
#	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-4 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/devices.csv-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/classrooms-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.devices.csv-5 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.classrooms-5 $(TESTDATA)
	@install -d $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.daytime.conf.default-school $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.nighttime.conf.default-school $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.all.conf.default-school $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.daytime.conf.bsz $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.nighttime.conf.bsz $(TESTDATA)/managementgroup-testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/managementgroup-testdata/wifi.all.conf.bsz $(TESTDATA)/managementgroup-testdata
# schoolisolation testdata
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-0.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-0.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-0.8859_1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-0.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-0.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-0.8859_1 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-1.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-2.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-3.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-3.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-4.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-4.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-5.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.extrastudents.csv-workflow-schoolisolation-5.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-5.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-6.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/extrastudents.csv-workflow-schoolisolation-6.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-6.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-10.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.extrastudents.csv-workflow-schoolisolation-10.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-10.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-11.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/extrastudents.csv-workflow-schoolisolation-11.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-11.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-12.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-12.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-13.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-13.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-14.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-14.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-15.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-15.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.students.csv-workflow-schoolisolation-16.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/bsz.teachers.csv-workflow-schoolisolation-16.utf8 $(TESTDATA)

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/students.csv-workflow-schoolisolation-17.utf8 $(TESTDATA)
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/teachers.csv-workflow-schoolisolation-17.utf8 $(TESTDATA)

# transfer testdata
	@install -d $(TESTDATA)/transfer-testdata
	@install -d $(TESTDATA)/transfer-testdata/subdir1-level1
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir2-level2
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2/subdir1-level3
	@install -d $(TESTDATA)/transfer-testdata/subdir2-level1/subdir3-level2
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/file* $(TESTDATA)/transfer-testdata

	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir1-level1/file* $(TESTDATA)/transfer-testdata/subdir1-level1
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir2-level1/file* $(TESTDATA)/transfer-testdata/subdir2-level1
	@install -oroot -groot --mode=0644 sophomorix-developer/testdata/transfer-testdata/subdir2-level1/subdir1-level2/file* $(TESTDATA)/transfer-testdata/subdir2-level1/subdir1-level2



# installing sources.list examples
#	@install -d $(TOOLS)/apt/s-lists
#	@install -oroot -groot --mode=0644 sophomorix-developer/tools/apt/s-lists/*sources.list $(TOOLS)/apt/s-lists


#clean-doc:
#	### clean-doc
#	rm -rf sophomorix-doc/html

# you need to: 
#       apt-get install docbook-utils
# on debian to create documentation
#doc:
#	### doc
## Creating html-documentation
#	cd ./sophomorix-doc/source/sgml; docbook2html --nochunks --output ../../html  sophomorix.sgml
## Creating html-manpages
#	./buildhelper/sopho-man2html
## Creating changelog
#	./buildhelper/sopho-changelog


