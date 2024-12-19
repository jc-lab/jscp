/** @type {import('ts-jest').JestConfigWithTsJest} **/
module.exports = {
  testEnvironment: "node",
  transformIgnorePatterns: [],
  // transform: {
  //   "^.+.tsx?$": ["ts-jest",{}],
  // },
  setupFilesAfterEnv: [
    '@sounisi5011/jest-binary-data-matchers'
  ],
};