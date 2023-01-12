import { AzureJwtError, invalidateCache, verifyAzureToken } from '../src';
import jwt from 'jsonwebtoken';
import nock from 'nock';
import discoveryResponse from './mocks/discovery-response.json';
jest.mock('jsonwebtoken');

const mocks = {
  options: { audience: 'AUD', issuer: 'ISS' },
  token: '$TOKEN',
  decoded: { foo: 'bar' },
  discoveryResponse,
};

const discovery = {
  host: 'https://login.microsoftonline.com',
  endpoint: '/common/discovery/keys',
  keyid: 'SsZsBNhZcF3Q9S4trpQBTByNRRI',
};

const key = `-----BEGIN CERTIFICATE-----\n${
  mocks.discoveryResponse.keys.find((k) => k.kid === discovery.keyid)?.x5c
}\n-----END CERTIFICATE-----`;

describe('The verify AzureAD JWT method', () => {
  let stubs: Record<string, jest.SpyInstance>;
  beforeEach(() => {
    stubs = {
      decode: jest.spyOn(jwt, 'decode'),
      verify: jest.spyOn(jwt, 'verify'),
    };
  });
  afterEach(() => {
    invalidateCache();
    stubs.verify.mockRestore();
    stubs.decode.mockRestore();
  });
  it('should decode token using public key provided by microsoft with the correct options', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    expect(await verifyAzureToken(mocks.token, mocks.options)).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(1);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(1);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should use key from cache if caching is activated and cache has not expired [given TTL]', async () => {
    const options = { ...mocks.options, useCache: true, cacheTtl: 200 };
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    nock(discovery.host).get(discovery.endpoint).replyWithError('Should not have been called !');
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    // First call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    // Second call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(2);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(2);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should use key from cache if caching is activated and cache has not expired [default TTL]', async () => {
    const options = { ...mocks.options };
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    nock(discovery.host).get(discovery.endpoint).replyWithError('Should not have been called !');
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    // First call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    // Second call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(2);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(2);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should fetch key again if caching is activated and cache has expired [given TTL]', async () => {
    const options = { ...mocks.options, useCache: true, cacheTtl: 100 };
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    // First call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    await new Promise<void>((resolve) => setTimeout(() => resolve(), 200));
    // Second call
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(2);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(2);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should fetch key again if caching is deactivated', async () => {
    const options = { ...mocks.options, useCache: false, cacheTtl: 100 };
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    // First call
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    // Second call
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    expect(await verifyAzureToken(mocks.token, options)).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(2);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(2);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should use provided discovery URL if given', async () => {
    const customUri = 'https://whatevr.com/';
    nock(customUri).get('/').reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    expect(
      await verifyAzureToken(mocks.token, {
        ...mocks.options,
        discoveryUrl: customUri,
        useCache: false,
      }),
    ).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(1);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(1);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should throw on 4xx when discovering keys', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(400, 'Bad Request');
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    try {
      await verifyAzureToken(mocks.token, { ...mocks.options, useCache: false });
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should retry twice on 5xx if no options given', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    expect(await verifyAzureToken(mocks.token, { ...mocks.options, useCache: false })).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(1);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(1);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should retry on network failure', async () => {
    nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    expect(await verifyAzureToken(mocks.token, { ...mocks.options, useCache: false })).toBe(mocks.decoded);
    expect(stubs.decode).toHaveBeenCalledTimes(1);
    expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
    expect(stubs.verify).toHaveBeenCalledTimes(1);
    expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
    expect(stubs.verify.mock.calls[0][1]).toEqual(key);
    expect(stubs.verify.mock.calls[0][2]).toEqual(mocks.options);
  });
  it('should retry once on 5xx if retry option is set to 1', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
    stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
    stubs.verify.mockImplementation((_token, _key, _options, callback) => {
      callback(null, mocks.decoded);
    });
    try {
      await verifyAzureToken(mocks.token, {
        ...mocks.options,
        maxRetries: 1,
        useCache: false,
      });
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw InvalidToken if token is falsy', async () => {
    try {
      await verifyAzureToken('');
    } catch (e) {
      expect((e as AzureJwtError).code).toBe('InvalidToken');
    }
  });
  it('should throw TokenNotDecoded if token is ill-formed', async () => {
    try {
      await verifyAzureToken('not-a-valid-token');
    } catch (e) {
      expect((e as AzureJwtError).code).toBe('TokenNotDecoded');
    }
  });
  it('should throw MissingKeyID if token header has no key ID', async () => {
    try {
      stubs.decode.mockImplementation(() => ({ header: { kid: undefined } }));
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('MissingKeyID');
    }
  });
  it('should throw ErrorFetchingKeys if call to retrieve microsoft keys returns status code different than 200', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
      nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
      nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
      stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw ErrorFetchingKeys if call to retrieve microsoft keys fails', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw InvalidDiscoveryResponse if the discovery response is invalid', async () => {
    try {
      stubs.decode.mockImplementation(() => ({ header: { kid: 'non-existing-key' } }));
      await verifyAzureToken(mocks.token, { discoveryUrl: 'https://www.google.com/' });
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw InvalidDiscoveryResponse if the discovery response is invalid', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, { foo: 'bar' });
      stubs.decode.mockImplementation(() => ({ header: { kid: 'non-existing-key' } }));
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw NotMatchingKey if there is no matching in microsoft response', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
      stubs.decode.mockImplementation(() => ({ header: { kid: 'non-existing-key' } }));
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect((e as AzureJwtError).code).toBe('NotMatchingKey');
    }
  });
  it('should throw JsonWebTokenError if token cannot be decoded', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
      stubs.decode.mockImplementation(() => ({ header: { kid: discovery.keyid } }));
      stubs.verify.mockImplementation((_token, _key, _options, callback) => {
        callback(new Error('Token expired'));
      });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(stubs.decode).toHaveBeenCalledTimes(1);
      expect(stubs.decode).toHaveBeenCalledWith(mocks.token, { complete: true });
      expect(stubs.verify).toHaveBeenCalledTimes(1);
      expect(stubs.verify.mock.calls[0][0]).toBe(mocks.token);
      expect(stubs.verify.mock.calls[0][1]).toEqual(key);
      expect((e as AzureJwtError).code).toBe('JsonWebTokenError');
      expect((e as AzureJwtError).message).toBe('Token expired');
    }
  });
});
