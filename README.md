# p2p-file-sharing

Express and Socket.IO service that registers users, issues JSON Web Tokens, and stores uploaded files encrypted with AES-256-CBC, with a React starter screen in `client/my-app`.

## Features

### Server (`server/index.js`)

- `POST /register` reads JSON `{ username, password }`, hashes the password with bcrypt at cost 10, and stores the user in an in-memory object. The response is `201` with the text `User registered`. A username that is already stored returns `400` and `User already exists`.
- `POST /login` checks the password with bcrypt. A match returns `200` and `{ "token": "<jwt>" }`. The token is an HS256 JSON Web Token and expires in one hour. A mismatch returns `400` and `Invalid credentials`.
- Socket.IO allows a connection when `handshake.auth.token` verifies with the same secret. A missing or invalid token ends the handshake with `Authentication error`.
- `uploadFile` expects `{ fileName, file }`. The server turns `file` into a `Buffer`, encrypts it with AES-256-CBC, and writes `server/uploads/<fileName>`. The IV is 16 random bytes prepended to the ciphertext. The `uploads` directory is created on the first upload.
- The uploading socket receives `uploadComplete` with `Upload successful` or `Upload failed`. Every connected socket receives `fileUploaded` with the file name.
- `downloadFile` expects the file name as a string. The server emits `fileData` as `{ fileName, file }`. `file` is the decrypted bytes, or `null` when the file cannot be read.
- HTTP and Socket.IO CORS both allow origin `http://localhost:3000`.

The user list is an in-memory object, so it is empty after a restart. Files written under `server/uploads/` remain on disk. The JWT secret and the AES key are string constants in `server/index.js`.

### Client (`client/my-app`)

- `src/App.js` renders the Create React App starter: the React logo, the sentence `Edit src/App.js and save to reload.`, and a “Learn React” link to `https://reactjs.org`.
- `src/App.test.js` checks that the text “learn react” is on the page.
- `src/index.js` mounts that component on `#root` and calls `reportWebVitals()` with no argument, so the web-vitals collectors are not started.
- `public/index.html` titles the document `React App`. `public/manifest.json` names it `Create React App Sample`.

`client/my-app/src` is the starter screen. Register, login, upload, and download are the server routes and events above.

## Tech stack

**Server** (`server/package.json`)

- Node.js (checked with Node.js 22)
- express `^4.19.2`
- socket.io `^4.7.5`
- jsonwebtoken `^9.0.2`
- bcrypt `^5.1.1`
- cors `^2.8.5`
- body-parser `^1.20.2`
- npm packages `http` `^0.0.1-security` and `crypto` `^1.0.1`
- Node built-in modules `fs` and `path`. From the `server/` directory, `require("http")` and `require("crypto")` still load the Node built-ins.

**Client** (`client/my-app/package.json`)

- react `^18.3.1` and react-dom `^18.3.1`
- react-scripts `5.0.1` (the `test` and `eject` scripts)
- `@testing-library/react` `^13.4.0`, `@testing-library/jest-dom` `^5.17.0`, `@testing-library/user-event` `^13.5.0`
- web-vitals `^2.1.4`
- Webpack `5.92.0` and webpack-dev-server `4.15.2` are transitive entries in `package-lock.json`. `webpack-cli` is not in that lockfile.

## Setup

### Server

`server/package.json` has no `start` script. The entry file is `server/index.js`. The process listens on `PORT`, or on port `5000` when `PORT` is unset.

`bcrypt` ships a native addon. The `bcrypt_lib.node` committed under `server/node_modules` is a Windows DLL, and loading it on Linux fails with `invalid ELF header`. Run `npm install` on the machine that will run the server so bcrypt can install a binary for that platform, then start the process:

```bash
cd server
npm install
node index.js
```

On success the process logs `Server running on port 5000`.

### Client

```bash
cd client/my-app
npm install
```

Scripts declared in `client/my-app/package.json`:

| Script | Command |
| --- | --- |
| `npm start` | `webpack serve --open` |
| `npm run build` | `webpack --mode production` |
| `npm test` | `react-scripts test` |
| `npm run eject` | `react-scripts eject` |

`npm start` and `npm run build` both launch the webpack binary, which then asks to install `webpack-cli` and exits if you decline. `webpack.config.js` only configures `resolve.fallback` (`stream-http`, `crypto-browserify`, `path-browserify`, `stream-browserify`, `buffer`, `browserify-zlib`, `util`, `os-browserify`, `assert`, `process/browser`, `querystring-es3`, `vm-browserify`) and a `ProvidePlugin` for `process` and `Buffer`. Those fallback packages are not dependencies. The file does not set `entry`, `module.rules`, or `devServer`.

`npm test` runs Jest through `react-scripts` and stays in watch mode in an interactive terminal. A one-shot run:

```bash
cd client/my-app
CI=true npm test -- --watchAll=false
```

That command runs `src/App.test.js`. The test `renders learn react link` passes.

## Usage

Start the server, then register and log in:

```bash
curl -sS -X POST http://localhost:5000/register \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret"}'
```

```bash
curl -sS -X POST http://localhost:5000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"secret"}'
```

A Socket.IO client connects to `http://localhost:5000` with the login token:

```js
io("http://localhost:5000", { auth: { token } });
```

This repository does not depend on `socket.io-client`. The events implemented in `server/index.js` are:

| Client emits | Payload | Server emits |
| --- | --- | --- |
| `uploadFile` | `{ fileName, file }` | `uploadComplete` to the sender (`Upload successful` or `Upload failed`); `fileUploaded` to every socket (the file name) |
| `downloadFile` | file name string | `fileData` with `{ fileName, file }` |

`file` on upload may be a string or binary data. Both are passed through `Buffer.from` before encryption. A string `"hello file"` and a second string `"second"` were uploaded and downloaded successfully against a locally running server: the files on disk were ciphertext, and `fileData` returned the original text. A download of a missing name returned `file: null`.

The React page has no control that calls these events. The server allowlist for browsers is `http://localhost:3000`.

## Project layout

```
server/index.js                 HTTP and Socket.IO entry
server/package.json
client/my-app/src/App.js        Starter screen
client/my-app/src/App.test.js   Link text test
client/my-app/public/           HTML template, icons, manifest
client/my-app/webpack.config.js Node polyfill fallbacks
LICENSE                         MIT License
```

## License

Released under the MIT License. Copyright (c) 2026 Farras Inas. See [LICENSE](LICENSE).
