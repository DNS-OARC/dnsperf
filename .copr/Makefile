top=..

all: srpm

prereq: $(top)/rpmbuild
	rpm -q git rpm-build >/dev/null || dnf -y install git rpm-build

update-dist-tools: $(top)/dist-tools
	( cd "$(top)/dist-tools" && git pull )

$(top)/dist-tools:
	git clone https://github.com/jelu/dist-tools.git "$(top)/dist-tools"

$(top)/rpmbuild:
	mkdir -p "$(top)"/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

srpm: prereq update-dist-tools
	test -f .gitmodules && git submodule update --init || true
	overwrite=yes nosign=yes "$(top)/dist-tools/create-source-packages" rpm
	cp ../*.orig.tar.gz "$(top)/rpmbuild/SOURCES/"
	rpmbuild -bs --define "%_topdir $(top)/rpmbuild" --undefine=dist "$(spec)"
	cp "$(top)"/rpmbuild/SRPMS/*.src.rpm "$(outdir)"
