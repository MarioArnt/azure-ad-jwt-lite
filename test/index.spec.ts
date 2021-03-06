import { verifyAzureToken } from '../src';
import { SinonStub, stub } from 'sinon';
import jsonwebtoken from 'jsonwebtoken';
import nock from 'nock';
import discoveryResponse from './mocks/discovery-response.json';

const mocks = {
  options: { audience: 'AUD', issuer: 'ISS' },
  token: '$TOKEN',
  decoded: { foo: 'bar' },
  discoveryResponse,
};

let stubs: {
  verify: SinonStub;
  decode: SinonStub;
};

const discovery = {
  host: 'https://login.microsoftonline.com',
  endpoint: '/common/discovery/keys',
  keyid: 'SsZsBNhZcF3Q9S4trpQBTByNRRI',
};

const key = `-----BEGIN CERTIFICATE-----\n${
  mocks.discoveryResponse.keys.find((k) => k.kid === discovery.keyid).x5c
}\n-----END CERTIFICATE-----`;

describe('The verify AzureAD JWT method', () => {
  beforeEach(() => {
    stubs = {
      verify: stub(jsonwebtoken, 'verify'),
      decode: stub(jsonwebtoken, 'decode'),
    };
  });
  afterEach(() => {
    stubs.verify.restore();
    stubs.decode.restore();
  });
  it('should decode token using public key provided by microsoft with the correct options', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    expect(await verifyAzureToken(mocks.token, mocks.options)).toBe(mocks.decoded);
  });
  it('should use provided discovery URL if given', async () => {
    const customUri = 'https://whatevr.com/';
    nock(customUri).get('/').reply(200, mocks.discoveryResponse);
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    expect(
      await verifyAzureToken(mocks.token, {
        ...mocks.options,
        discoveryUrl: customUri,
      }),
    ).toBe(mocks.decoded);
  });
  it('should throw on 4xx when discovering keys', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(400, 'Bad Request');
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    try {
      await verifyAzureToken(mocks.token, mocks.options);
    } catch (e) {
      expect(e.code).toBe('ErrorFetchingKeys');
    }
  });
  it('should retry twice on 5xx if no options given', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    expect(await verifyAzureToken(mocks.token, mocks.options)).toBe(mocks.decoded);
  });
  it('should retry on network failure', async () => {
    nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    expect(await verifyAzureToken(mocks.token, mocks.options)).toBe(mocks.decoded);
  });
  it('should retry once on 5xx if retry option is set to 1', async () => {
    nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
    nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
    stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
    stubs.verify.withArgs(mocks.token, key, mocks.options).yields(null, mocks.decoded);
    try {
      await verifyAzureToken(mocks.token, {
        ...mocks.options,
        maxRetries: 1,
      });
    } catch (e) {
      expect(e.code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw InvalidToken if token is falsy', async () => {
    try {
      await verifyAzureToken('');
    } catch (e) {
      expect(e.code).toBe('InvalidToken');
    }
  });
  it('should throw TokenNotDecoded if token is ill-formed', async () => {
    try {
      await verifyAzureToken('not-a-valid-token');
    } catch (e) {
      expect(e.code).toBe('TokenNotDecoded');
    }
  });
  it('should throw MissingKeyID if token header has no key ID', async () => {
    try {
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: undefined } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('MissingKeyID');
    }
  });
  it('should throw ErrorFetchingKeys if call to retrieve microsoft keys returns status code different than 200', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
      nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
      nock(discovery.host).get(discovery.endpoint).reply(502, 'Bad Gateway');
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw ErrorFetchingKeys if call to retrieve microsoft keys fails', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      nock(discovery.host).get(discovery.endpoint).replyWithError('Network Failure :S');
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('ErrorFetchingKeys');
    }
  });
  it('should throw InvalidDiscoveryResponse if the discovery response is invalid', async () => {
    try {
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: 'non-existing-key' } });
      await verifyAzureToken(mocks.token, { discoveryUrl: 'https://www.google.com/' });
    } catch (e) {
      expect(e.code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw InvalidDiscoveryResponse if the discovery response is invalid', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, { foo: 'bar' });
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: 'non-existing-key' } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('InvalidDiscoveryResponse');
    }
  });
  it('should throw NotMatchingKey if there is no matching in microsoft response', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: 'non-existing-key' } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('NotMatchingKey');
    }
  });
  it('should throw JsonWebTokenError if token cannot be decoded', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(200, mocks.discoveryResponse);
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
      stubs.verify.withArgs(mocks.token, key).yields(new Error('Token expired'), null);
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('JsonWebTokenError');
      expect(e.message).toBe('Token expired');
    }
  });
});
