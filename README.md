# azure-ad-jwt-lite

![npm bundle size](https://img.shields.io/bundlephobia/minzip/azure-ad-jwt-lite)
![npm](https://img.shields.io/npm/dm/azure-ad-jwt-lite)
![Snyk Vulnerabilities for GitHub Repo](https://img.shields.io/snyk/vulnerabilities/github/MarioArnt/azure-ad-jwt-lite)

![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/MarioArnt/azure-ad-jwt-lite/publish.yml)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=coverage)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Duplicated Lines (%)](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=duplicated_lines_density)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Maintainability Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=sqale_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Reliability Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=reliability_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Security Rating](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=security_rating)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Technical Debt](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=sqale_index)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Bugs](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=bugs)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)
[![Code Smells](https://sonarcloud.io/api/project_badges/measure?project=MarioArnt_azure-ad-jwt-lite&metric=code_smells)](https://sonarcloud.io/dashboard?id=MarioArnt_azure-ad-jwt-lite)

<p align="center">
  <img src="https://github.com/MarioArnt/azure-ad-jwt-lite/blob/main/logo.png?raw=true" alt="Logo"/>
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

const decoded = await verifyAzureToken(token);
```

You can add any option supported by [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken):

```typescript
import { verifyAzureToken } from 'azure-ad-jwt-lite';

const decoded = await verifyAzureToken(token, {
  audience: process.env.JWT_AUD,
  issuer: process.env.JWT_ISS,
});
```

## Additional options

* Discovery URL: The URL to fetch Microsoft public keys (defaults to https://login.microsoftonline.com/common/discovery/keys)

* Retries on 5xx: set the number of retries when request to fetch keys returns a 5xx response (defaults to 2)


```typescript
import { verifyAzureToken } from 'azure-ad-jwt-lite';

const decoded = await verifyAzureToken(token, {
  discoveryUrl: `https://login.microsoftonline.com/${process.env.TENANT}/discovery/keys?appid=${process.env.APP_ID}`,
  maxRetries: 5,
  audience: process.env.JWT_AUD,
  issuer: process.env.JWT_ISS,
});
```

### Caching keys

Public keys from discovery endpoint calls are cached for a default TTL of 5 minutes.

You can disable caching using ``useCache: false`` in options, or modify TTL using `cacheTtl` option.

## Error reference

The lib will throw the following errors if something wrong happends during decoding token:

 * `InvalidToken`: the token provided is not a non-empty string.
 * `TokenNotDecoded`: the token cannot be decoded. This usually means the token is ill-formed.
 * `MissingKeyID`: no `kid` (Microsoft Key ID) field is present in JWT header.
 * `ErrorFetchingKeys`: API call to fetch Microsoft public keys failed.
 * `NotMatchingKey`: no matching key is found in Microsoft response.
 * `JsonWebTokenError`: token cannot be verified, the human-readable reason is provided (expired, audience mismatch etc...)
