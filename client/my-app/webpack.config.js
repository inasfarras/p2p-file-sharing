// client/my-app/webpack.config.js
const webpack = require("webpack");

module.exports = {
  resolve: {
    fallback: {
      http: require.resolve("stream-http"),
      crypto: require.resolve("crypto-browserify"),
      path: require.resolve("path-browserify"),
      stream: require.resolve("stream-browserify"),
      buffer: require.resolve("buffer"),
      zlib: require.resolve("browserify-zlib"),
      util: require.resolve("util"),
      os: require.resolve("os-browserify"),
      assert: require.resolve("assert"),
      process: require.resolve("process/browser"),
      querystring: require.resolve("querystring-es3"),
      vm: require.resolve("vm-browserify"),
    },
  },
  plugins: [
    new webpack.ProvidePlugin({
      process: "process/browser",
      Buffer: ["buffer", "Buffer"],
    }),
  ],
};
