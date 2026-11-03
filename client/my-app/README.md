# my-app

React 18 starter screen in the p2p-file-sharing repository. The page is the Create React App default. Register, login, and encrypted upload and download are implemented in [`server/index.js`](../../server/index.js) and described in the [repository README](../../README.md).

## Features

- `src/App.js` shows the React logo, `Edit src/App.js and save to reload.`, and a “Learn React” link to `https://reactjs.org`.
- `src/App.test.js` looks for the text “learn react”.
- `public/index.html` sets the document title to `React App`.
- `public/manifest.json` sets `short_name` to `React App` and `name` to `Create React App Sample`.
- `src/index.js` calls `reportWebVitals()` with no callback.

## Tech stack

From `package.json`:

- react `^18.3.1` and react-dom `^18.3.1`
- react-scripts `5.0.1`
- `@testing-library/react` `^13.4.0`, `@testing-library/jest-dom` `^5.17.0`, `@testing-library/user-event` `^13.5.0`
- web-vitals `^2.1.4`

`package-lock.json` also includes webpack `5.92.0` and webpack-dev-server `4.15.2` as transitive dependencies of react-scripts. `webpack-cli` is absent from the lockfile.

## Setup

```bash
npm install
```

| Script | Command |
| --- | --- |
| `npm start` | `webpack serve --open` |
| `npm run build` | `webpack --mode production` |
| `npm test` | `react-scripts test` |
| `npm run eject` | `react-scripts eject` |

`npm start` and `npm run build` reach the webpack binary, which prompts to install `webpack-cli` and exits when that install is declined. `webpack.config.js` sets `resolve.fallback` for `stream-http`, `crypto-browserify`, `path-browserify`, `stream-browserify`, `buffer`, `browserify-zlib`, `util`, `os-browserify`, `assert`, `process/browser`, `querystring-es3`, and `vm-browserify`, and it injects `process` and `Buffer` with `ProvidePlugin`. Those fallback packages are not listed in `package.json`. The config has no `entry`, `module.rules`, or `devServer`.

`npm test` starts Jest in watch mode. Run the suite once with:

```bash
CI=true npm test -- --watchAll=false
```

`src/App.test.js` passes under that command. The test name is `renders learn react link`.

## Usage

The screen in `src/App.js` is the starter page above. To register a user, log in, or transfer a file, use the server documented in the [repository README](../../README.md). That server allows cross-origin calls from `http://localhost:3000`.

## License

This package is part of p2p-file-sharing, released under the MIT License. Copyright (c) 2026 Farras Inas. See [LICENSE](../../LICENSE).
