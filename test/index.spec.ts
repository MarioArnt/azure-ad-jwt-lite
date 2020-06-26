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
  it('should throw ErrorFetchingKeys if call to retrieve microsoft keys fails', async () => {
    try {
      nock(discovery.host).get(discovery.endpoint).reply(503, 'Service Unavailable');
      stubs.decode.withArgs(mocks.token, { complete: true }).returns({ header: { kid: discovery.keyid } });
      await verifyAzureToken(mocks.token);
    } catch (e) {
      expect(e.code).toBe('ErrorFetchingKeys');
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
