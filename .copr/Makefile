top=..

all: srpm

prereq:
	rpm -q git rpm-build >/dev/null || dnf -y install git rpm-build

$(top)/dist-tools:
	git clone https://github.com/jelu/dist-tools.git $(top)/dist-tools

$(top)/rpmbuild:
	mkdir -p $(top)/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

srpm: prereq $(top)/dist-tools $(top)/rpmbuild
	git checkout -b autobuild
	nosign=yes $(top)/dist-tools/create-source-packages rpm
	cp ../*.orig.tar.gz $(top)/rpmbuild/SOURCES/
	rpmbuild -bs --define "%_topdir $(top)/rpmbuild" --undefine=dist "$(spec)"
	cp $(top)/rpmbuild/SRPMS/*.src.rpm "$(outdir)"
