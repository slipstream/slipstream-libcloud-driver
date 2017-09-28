
gh-pages:
	git checkout gh-pages
	rm .git/index || true
	git clean -fdx
	git checkout master doc/Makefile doc/source src
	git reset HEAD
	cd doc; make html
	cp -rfv doc/build/html/. ./
	rm -rf doc src
	git add -A && git commit -m "Generated gh-pages for `git log master -1 --pretty=short --abbrev-commit`" && git push origin gh-pages ; git checkout master

