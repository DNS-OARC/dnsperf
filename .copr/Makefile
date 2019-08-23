srpm:
	dnf -y install git rpm-build
	git checkout -b autobuild
	git clone https://github.com/jelu/dist-tools.git ../dist-tools
	nosign=yes ../dist-tools/create-source-packages rpm
	mkdir -p ../rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
	cp ../*.orig.tar.gz ../rpmbuild/SOURCES/
	rpmbuild -bs --define "%_topdir ../rpmbuild" --undefine=dist "$(spec)"
	cp ../rpmbuild/SRPMS/*.src.rpm "$(outdir)"
