# @new10com/jwks-rsa

[![NPM version][npm-image]][npm-url]
[![NPM downloads][download-image]][npm-url]
[![Release][release-image]][release-url]
[![Install Size][install-size-image]][install-size-url]

[npm-image]: https://img.shields.io/npm/v/@new10com/jwks-rsa.svg
[npm-url]: https://www.npmjs.org/package/@new10com/jwks-rsa
[download-image]: https://img.shields.io/npm/dm/@new10com/jwks-rsa.svg
[release-image]: https://img.shields.io/github/release/new10com/node-jwks-rsa.svg
[release-url]: https://github.com/new10com/node-jwks-rsa/releases/latest
[install-size-image]: https://packagephobia.now.sh/badge?p=@new10com/jwks-rsa
[install-size-url]: https://packagephobia.now.sh/result?p=@new10com/jwks-rsa

A library to retrieve RSA signing keys from a JWKS (JSON Web Key Set) endpoint.

> npm install @new10com/jwks-rsa

## Usage

You'll provide the client with the JWKS endpoint which exposes your signing keys. Using the `getSigningKey` you can then get the signing key that matches a specific `kid`.

```js
const jwksClient = require('@new10com/jwks-rsa');

const client = jwksClient({
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json',
  strictSsl: true, // default value
  followRedirect: true, // default value, see https://github.com/sindresorhus/got/tree/v9.5.0#followredirect
  retry: 0, // default value, see https://github.com/sindresorhus/got/tree/v9.5.0#retry
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.rsaPublicKey;

  // Now I can use this to configure my Express or Hapi middleware
});
```

Integrations are also provided with:

 - [express/express-jwt](examples/express-demo)
 - [hapi/hapi-auth-jwt2](examples/hapi-demo)
 - [koa/koa-jwt](examples/koa-demo)

### Caching

In order to prevent a call to be made each time a signing key needs to be retrieved you can also configure a cache as follows. If a signing key matching the `kid` is found, this will be cached and the next time this `kid` is requested the signing key will be served from the cache instead of calling back to the JWKS endpoint.

```js
const jwksClient = require('@new10com/jwks-rsa');

const client = jwksClient({
  cache: true,
  cacheMaxEntries: 5, // Default value
  cacheMaxAge: ms('10h'), // Default value
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.rsaPublicKey;

  // Now I can use this to configure my Express or Hapi middleware
});
```

### Rate Limiting

Even if caching is enabled the library will call the JWKS endpoint if the `kid` is not available in the cache, because a key rotation could have taken place. To prevent attackers to send many random `kid`s you can also configure rate limiting. This will allow you to limit the number of calls that are made to the JWKS endpoint per minute (because it would be highly unlikely that signing keys are rotated multiple times per minute).

```js
const jwksClient = require('@new10com/jwks-rsa');

const client = jwksClient({
  cache: true,
  rateLimit: true,
  jwksRequestsPerMinute: 10, // Default value
  jwksUri: 'https://sandrino.auth0.com/.well-known/jwks.json'
});

const kid = 'RkI5MjI5OUY5ODc1N0Q4QzM0OUYzNkVGMTJDOUEzQkFCOTU3NjE2Rg';
client.getSigningKey(kid, (err, key) => {
  const signingKey = key.publicKey || key.rsaPublicKey;

  // Now I can use this to configure my Express or Hapi middleware
});
```

## Running Tests

```
npm run test
```

## Showing Trace Logs

To show trace logs you can set the following environment variable:

```
DEBUG=jwks
```

Output:

```
jwks Retrieving keys from http://my-authz-server/.well-known/jwks.json +5ms
jwks Keys: +8ms [ { alg: 'RS256',
  kty: 'RSA',
  use: 'sig',
  x5c: [ 'pk1' ],
  kid: 'ABC' },
{ alg: 'RS256', kty: 'RSA', use: 'sig', x5c: [], kid: '123' } ]
```
