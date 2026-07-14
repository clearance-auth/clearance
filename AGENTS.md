we are building an open source auth platform called clearance
clear is a well designed alternative to clerk/workos

focus entirely on high quality and engineering, spending as little time as possible on tests and smoke test

all truely great testing comes from using working software, not running scripts

all workflows need to be enabled via CLI to enable developer productivity

all workflows need to be incredibly clear and simple (not simplistic)

## Release

Treat `npm publish` as pending until the public registry returns SHA-512 integrity and signed provenance; first-publish 404s can be stale negative-cache responses, so retry read-back for up to 10 minutes.
Republish only absent versions; if a rebuild has different bytes, recover only after every existing package's signed provenance binds it to the exact tag commit, then attach assets without republishing.
Sequence releases as: finish every release-path change, rehearse the exact publish or recovery path locally, run the complete CI matrix once, then push once.
Any release-path failure resets the gate: reproduce and fix it locally, rerun the exact rehearsal and full local CI, and only then trigger another remote run.
Run the exact CI matrix under every supported Node version before the monolithic release rehearsal; success on one runtime is no evidence for another.
Diagnose the first non-zero setup command and assert it before parsing downstream output; never debug the secondary exception first.
After a fix, repeat the targeted reproducer, then rerun only invalidated lanes; reset ops, packaging, and publication proof only when shipping code or release configuration changed.
Freeze the candidate before expensive proof: finish code and security fixes, remove prohibited references, and finalize versions, pins, and workflows; any later source or release-config change invalidates downstream rehearsal and CI evidence.
Keep terminal actions last and in dependency order: exact local rehearsal, full local CI, one push, hosted CI, signed publication, anonymous install and pull, evidence attachment, then public visibility and documentation.
Before tagging, rehearse every release entry path with the candidate workflow: provision every tool used by nested verification, validate the guarded workflow ref and OIDC signing or verification identity for tag pushes and explicit recovery, and create the immutable tag only after those checks pass.
Use a tag-triggered run for first publication so npm provenance binds the package bytes to that tag and commit; reserve branch dispatch for provenance-verified recovery of versions that already exist in the registry.
