import { get } from 'https';
import { IncomingMessage } from 'http';
import { VerifyOptions, decode, verify } from 'jsonwebtoken';

const DISCOVERY_URL = 'https://login.microsoftonline.com/common/discovery/keys';
const RETRIES = 2;

export interface DecodeOptions extends VerifyOptions {
  discoveryUrl?: string;
  maxRetries?: number;
  useCache?: boolean;
  cacheTtl?: number;
}

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
  | 'InvalidDiscoveryResponse'
  | 'JsonWebTokenError';

export class AzureJwtError extends Error {
  code: ErrorCode;
  details: Error;
  constructor(code: ErrorCode, msg: string, details?: Error) {
    super(msg);
    this.code = code;
    this.details = details;
  }
}

const invalidPayloadError = (discoveryURL: string) =>
  new AzureJwtError(
    'InvalidDiscoveryResponse',
    `API call to discovery URL ${discoveryURL} returned an invalid response`,
  );

const throwError = (err: Error): Error => {
  return new AzureJwtError('ErrorFetchingKeys', 'An error occurred retrieving public keys from Microsoft API', err);
};

/**
 * Retry request on network failure or on 5xx
 */
const retry = (err: Error, attempt: number, retries: number, options: DecodeOptions): Promise<Array<IMicrosoftKey>> => {
  return new Promise((resolve, reject) => {
    if (attempt >= retries) {
      return reject(throwError(err));
    }
    return getKeys(options, attempt + 1)
      .then(resolve)
      .catch(reject);
  });
};

/**
 * Verify that payload response is on the expected format
 */
const verifyResponse = (data: string): IMicrosoftKey[] => {
  const validated = JSON.parse(data) as { keys: IMicrosoftKey[] };
  if (validated.keys && Array.isArray(validated.keys) && validated.keys.every((key) => key.x5c != null)) {
    return validated.keys;
  }
  throw new Error('Invalid Payload');
};

/**
 * Handle HTTP GET discovery url response.
 * Retries on 5xx.
 */
const onResponse = (
  response: IncomingMessage,
  data: string,
  attempt: number,
  retries: number,
  options: DecodeOptions,
  url: string,
): Promise<Array<IMicrosoftKey>> => {
  return new Promise((resolve, reject) => {
    if (response.statusCode !== 200) {
      const error = new Error(`Server answered with status code ${response.statusCode}`);
      if (response.statusCode > 499 && response.statusCode < 600) {
        // Retry on 5XX
        return retry(error, attempt, retries, options).then(resolve).catch(reject);
      }
      return reject(throwError(error));
    }
    try {
      const keys = verifyResponse(data);
      return resolve(keys);
    } catch (e) {
      return reject(invalidPayloadError(url));
    }
  });
};

const cachedKeys: { obtainedAt?: number; value?: IMicrosoftKey[] } = {};
const FIVE_MINUTES = 5 * 60 * 1000;
const DEFAULT_CACHE_TTL = FIVE_MINUTES;

/**
 * Fetch Microsoft public keys with API call and build.
 * @returns they public keys corresponding to the private keys used by microsoft to sign token.
 * @throws ErrorFetchingKeys if API call fails for some reason.
 */
const getKeys = async (options: DecodeOptions, attempt = 0): Promise<Array<IMicrosoftKey>> => {
  const discoveryURL = options && options.discoveryUrl != null ? options.discoveryUrl : DISCOVERY_URL;
  const retries = options && options.maxRetries != null ? options.maxRetries : RETRIES;
  const useCache = !options || options.useCache !== false;
  const isExpired =
    cachedKeys.obtainedAt && Date.now() - cachedKeys.obtainedAt > (options.cacheTtl || DEFAULT_CACHE_TTL);
  if (useCache && cachedKeys.value && !isExpired) {
    return cachedKeys.value;
  }
  const keys = await new Promise<Array<IMicrosoftKey>>((resolve, reject) => {
    get(discoveryURL, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });
      res.on('end', () => onResponse(res, data, attempt, retries, options, discoveryURL).then(resolve).catch(reject));
    }).on('error', (err) => retry(err, attempt, retries, options).then(resolve).catch(reject));
  });
  if (useCache) {
    cachedKeys.value = keys;
    cachedKeys.obtainedAt = Date.now();
  }
  return keys;
};

/**
 * Fetch Microsoft public keys with API call and build.
 * @param options - the JWT options enriched with caching and discovery options
 * @param kid - the key ID used to sign token. This comes from JWT header.
 * @returns the properly formatted public key corresponding to the given key ID.
 * @throws NotMatchingKey - If no matching key is found in microsoft response.
 */
const buildKey = async (options: DecodeOptions, kid: string) => {
  const keys = await getKeys(options);
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
 * @param key - the public key corresponding to the private key that signed token.
 * @param options - any options supported by jsonwebtoken
 * @throws JsonWebTokenError with the human-readable reason if token cannot be verified.
 * @returns resolves the decoded token payload if succeeds.
 */
const verifyJWT = async (token: string, key: string, options: DecodeOptions): Promise<unknown> => {
  const extractOptions = (): VerifyOptions => {
    const decodeOptions = { ...options };
    delete decodeOptions.maxRetries;
    delete decodeOptions.discoveryUrl;
    delete decodeOptions.useCache;
    delete decodeOptions.cacheTtl;
    return decodeOptions;
  };
  return new Promise((resolve, reject) => {
    verify(token, key, extractOptions(), (err, decoded) => {
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
 * @returns resolves the decoded token payload if verification succeeds.
 */
export const verifyAzureToken = async (token: string, options?: DecodeOptions): Promise<unknown> => {
  if (!token || typeof token !== 'string') {
    throw new AzureJwtError('InvalidToken', 'Token provided must be a non-empty string');
  }
  const decoded = decode(token, { complete: true }) as IDecodedToken;
  if (!decoded) {
    throw new AzureJwtError(
      'TokenNotDecoded',
      'An error occurred decoding you JWT. Check that your token is a well-formed JWT',
    );
  }
  const kid = decoded.header.kid;
  if (!kid) {
    throw new AzureJwtError(
      'MissingKeyID',
      'The given JWT has no kid. Please double-check it is a valid AzureAD token.',
    );
  }
  const key = await buildKey(options, kid);
  return verifyJWT(token, key, options);
};

export const invalidateCache = () => {
  cachedKeys.value = undefined;
  cachedKeys.obtainedAt = undefined;
};
