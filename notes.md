


Todo
====
drop generators for async
	async_std maybe - if so probably also async_tls

monitor mapped files/directories for changes so they can be reloaded
	when caching enabled, evict files from caches on any change event
	potentially scheduling them for eager reload?
	alternatively only load and recompress on request

build in acme client

switch to notify

BETTER HTTP SWEET LORD


Desirable
---------
wildcards for mappings
infer mime type from extensions
specify temp mappings on command line
specify mapping file on command line


Data n whatnot
==============

ResourceMapping/Cache
	URI => Resource

Resource
	Can be:
	- just a file path, reread and optionally compressed on request
	- the contents of a file, in optionally compressed forms
	- generated data - similar to the above, except has no link to an resource on the file system

	if a cached file, a fs watch, so it can be reloaded on change?
		if a whole directory is being watched possibly not necessary
		maybe this should be handled by the cache itself

	Directories?

Server
	TcpListener
	optionally with TLS
	when TLS is enabled:
		there _must_ be a non-TLS listener that redirects to the TLS port
		start certificate autorenew thread to rerun acme challenges and update cert
			could _probably_ just be an async operation - doesn't necessarily need to be its own thread

FileWatcher?
	watch files and send signals to cache 