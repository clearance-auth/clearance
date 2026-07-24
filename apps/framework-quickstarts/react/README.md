# React quickstart

This browser app uses `@clearance/runtime/react` for email/password sign-in,
sign-out, and cookie-backed session state.

```sh
export VITE_CLEARANCE_URL="http://localhost:3300"
pnpm --filter @clearance/framework-quickstarts dev:react
```

Open the Vite URL and sign in with a Clearance user. Browser code uses only the
Clearance React client; token verification remains in the Express and Next
server examples.
