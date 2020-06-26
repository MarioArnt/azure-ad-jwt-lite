import { get } from 'https';
import { VerifyOptions, decode, verify } from 'jsonwebtoken';

const discoveryUrl = 'https://login.microsoftonline.com/common/discovery/keys';

export type DecodeOptions = VerifyOptions;

interface IMicrosoftKey {
  kty: string;
  use: string;
  kid: string;
  x5t: string;
  n: string;
  e: string;
  x5c: string;
}

interface IDecodedToken {
  header: { kid?: string };
}

type ErrorCode =
  | 'NotMatchingKey'
  | 'TokenNotDecoded'
  | 'InvalidToken'
  | 'MissingKeyID'
  | 'ErrorFetchingKeys'
  | 'JsonWebTokenError';

class AzureJwtError extends Error {
  code: ErrorCode;
  details: Error;
  constructor(code: ErrorCode, msg: string, details?: Error) {
    super(msg);
    this.code = code;
    this.details = details;
  }
}

/**
 * Fetch Microsoft public keys with API call and build.
 * @returns they public keys corresponding to the private keys used by microsoft to sign token.
 * @throws ErrorFetchingKeys if API call fails for some reason.
 */
const getKeys = async (): Promise<Array<IMicrosoftKey>> => {
  const throwError = (err: Error): Error => {
    return new AzureJwtError('ErrorFetchingKeys', 'An error occured retrieving public keys from Microsoft API', err);
  };
  return new Promise((resolve, reject) => {
    get(discoveryUrl, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => {
        if (res.statusCode !== 200) {
          return reject(throwError(new Error(`Server answered with status code ${res.statusCode}`)));
        }
        const response = JSON.parse(data);
        return resolve(response.keys);
      });
    }).on('error', (err) => {
      return reject(throwError(err));
    });
  });
};

/**
 * Fetch Microsoft public keys with API call and build.
 * @param kid - the key ID used to sign token. This comes from JWT header.
 * @returns the properly formatted public key corrsponding to the given key ID.
 * @throws NotMatchingKey - If no matching key is found in microsoft response.
 */
const buildKey = async (kid: string) => {
  const keys = await getKeys();
  const matchingKey = keys.find((k) => k.kid === kid);
  if (!matchingKey) {
    throw new AzureJwtError(
      'NotMatchingKey',
      'A key matching your token kid cannot  be found in Microsoft public keys',
    );
  }
  const begin = '-----BEGIN CERTIFICATE-----';
  const end = '-----END CERTIFICATE-----';
  return `${begin}\n${matchingKey.x5c}\n${end}`;
};

/**
 * Asynchronously verify JSON Web Token using official Auth0 library.
 * @param token - the encoded token.
 * @param key - the public key corresponding to the private key thats signed token.
 * @throws JsonWebTokenError with the human-readable reason if token cannot be verified.
 * @returns resolves the decoded token payload if suceeds.
 */
const verifyJWT = async (token: string, key: string, options: DecodeOptions): Promise<unknown> => {
  return new Promise((resolve, reject) => {
    verify(token, key, options, (err, decoded) => {
      if (err) {
        return reject(new AzureJwtError('JsonWebTokenError', err.message));
      }
      return resolve(decoded);
    });
  });
};

/**
 * Verify an AzureAD JSON web token using the given options if any.
 * @param token - the encoded token.
 * @param options - jsonwebtoken supported options such issuer and audience.
 * @see https://www.npmjs.com/package/jsonwebtoken for all available options.
 * @throws InvalidToken if the token provided is not a non-empty string.
 * @throws TokenNotDecoded if the token cannot be decoded. This usually means the token is ill-formed.
 * @throws MissingKeyID if no kid field is present in JWT header.
 * @throws ErrorFetchingKeys if API call to fetch Microsoft public keys fails for some reason.
 * @throws NotMatchingKey - If no matching key is found in Microsoft response.
 * @throws JsonWebTokenError with a human-readable error message if token cannot be verified.
 * @returns resolves the decoded token payload if verification suceeds.
 */
export const verifyAzureToken = async (token: string, options?: DecodeOptions): Promise<unknown> => {
  if (!token || typeof token !== 'string') {
    throw new AzureJwtError('InvalidToken', 'Token provided must be a non-empty string');
  }
  const decoded = decode(token, { complete: true }) as IDecodedToken;
  if (!decoded) {
    throw new AzureJwtError(
      'TokenNotDecoded',
      'An error occured decoding you JWT. Check that your token is a well-formed JWT',
    );
  }
  const kid = decoded.header.kid;
  if (!kid) {
    throw new AzureJwtError(
      'MissingKeyID',
      'The given JWT has no kid. Please double-check it is a valid AzureAD token.',
    );
  }
  const key = await buildKey(kid);
  return verifyJWT(token, key, options);
};
