# azure-ad-jwt-lite
[![Build Status](https://travis-ci.com/MarioArnt/azure-ad-jwt-lite.svg?branch=master)](https://travis-ci.com/MarioArnt/azure-ad-jwt-lite)
[![codecov](https://codecov.io/gh/MarioArnt/azure-ad-jwt-lite/branch/master/graph/badge.svg)](https://codecov.io/gh/MarioArnt/azure-ad-jwt-lite)
[![Known Vulnerabilities](https://snyk.io/test/github/MarioArnt/azure-ad-jwt-lite/badge.svg?targetFile=package.json)](https://snyk.io/test/github/MarioArnt/azure-ad-jwt-lite?targetFile=package.json)
[![Maintainability](https://api.codeclimate.com/v1/badges/383bd57e1d158baf0b2c/maintainability)](https://codeclimate.com/github/MarioArnt/azure-ad-jwt-lite/maintainability)

<p align="center">
  <img src="https://github.com/MarioArnt/azure-ad-jwt-lite/blob/master/logo.png?raw=true" alt="Logo"/>
</p>

Lightweight library to verify AzureAD JSON Web Tokens.

It weights around 12KB alone and less than 320KB with its only one dependeny: [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)

Other libraries generally includes `request` and are bloated. I decided to write this lib because the previous helper I used weighted more than 4MB with all its dependencies!

Futhermore, it is written in typescript and provide its own type definitions.

Last but not least, it is unit tested with one-hundred percent test coverage.

## Getting started

Install the package using yarn or NPM: `npm i azure-ad-jwt-lite`

Do not forget to install `jsonwebtoken` types definitions as dev dependency if you are using Typescript: `npm i -D @types/jsonwebtoken`.

In your authentication middleware decode and verify the token using:

```typescript
import { verifyAzureToken } from 'azure-ad-jwt-lite';

const decoded = verifyAzureToken(token);
```

You can add any option supported by [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken):

```typescript
import { verifyAzureToken } from 'azure-ad-jwt-lite';

const decoded = verifyAzureToken(token, {
  audience: process.env.JWT_AUD,
  issuer: process.env.JWT_ISS,
});
```

## Additional options

* Discovery URL: The URL to fetch Microsoft public keys (defaults to https://login.microsoftonline.com/common/discovery/keys)

* Retries on 5xx: set the number of retries when request to fetch keys returns a 5xx response (defaults to 2)


```typescript
import { verifyAzureToken } from 'azure-ad-jwt-lite';

const decoded = verifyAzureToken(token, {
  discoveryUrl: `https://login.microsoftonline.com/${process.env.TENANT}/discovery/keys?appid=${process.env.APP_ID}`,
  maxRetries: 5,
  audience: process.env.JWT_AUD,
  issuer: process.env.JWT_ISS,
});
```

## Error reference

The lib will throw the following errors if something wrong happends during decoding token:

 * `InvalidToken`: the token provided is not a non-empty string.
 * `TokenNotDecoded`: the token cannot be decoded. This usually means the token is ill-formed.
 * `MissingKeyID`: no `kid` (Microsoft Key ID) field is present in JWT header.
 * `ErrorFetchingKeys`: API call to fetch Microsoft public keys failed.
 * `NotMatchingKey`: no matching key is found in Microsoft response.
 * `JsonWebTokenError`: token cannot be verified, the human-readable reason is provided (expired, audience mismatch etc...)
