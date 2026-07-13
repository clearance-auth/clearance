we are building an open source auth platform called clearance
clear is a well designed alternative to clerk/workos

focus entirely on high quality and engineering, spending as little time as possible on tests and smoke test

all truely great testing comes from using working software, not running scripts

all workflows need to be enabled via CLI to enable developer productivity

all workflows need to be incredibly clear and simple (not simplistic)

## Release

Treat `npm publish` as pending until the public registry returns SHA-512 integrity and signed provenance; first-publish 404s can be stale negative-cache responses, so retry read-back for up to 10 minutes.
Republish only absent versions; if a rebuild has different bytes, recover only after every existing package's signed provenance binds it to the exact tag commit, then attach assets without republishing.
