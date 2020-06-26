# azure-ad-jwt-lite

Lightweight library to verify AzureAD JSON Web Tokens.

It weights less than 320 kilobytes and has only one dependeny: [jsonwebtoken](https://www.npmjs.com/package/jsonwebtoken)

Other libraries generally includes `request` and are bloated. I decided to write this lib because the previous helper I used weighted more than 4MB !

## Getting started

Install the package using yarn or NPM: `npm i azure-ad-jwt-lite`

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

## Error reference

The lib will throw the following errors if something wrong happends during decoding token:

 * `InvalidToken`: the token provided is not a non-empty string.
 * `TokenNotDecoded`: the token cannot be decoded. This usually means the token is ill-formed.
 * `MissingKeyID`: no `kid` (Microsoft Key ID) field is present in JWT header.
 * `ErrorFetchingKeys`: API call to fetch Microsoft public keys failed.
 * `NotMatchingKey`: no matching key is found in Microsoft response.
 * `JsonWebTokenError`: token cannot be verified, the human-readable reason is provided (expired, audience mismatch etc...)
