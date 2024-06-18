import assert from 'assert';
import crypto from 'crypto';
import { BigInteger } from 'jsbn';

export const getHash = (data: Buffer | string, length: number): string => {
  const hash = crypto.createHash('sha256').update(data).digest('hex');

  return hash.padStart(length * 2, '0');
};

export const calculatePrivateKey = (
  poolname: string,
  username: string,
  password: string,
  salt: string,
): BigInteger => {
  // x = H(s,p)
  const hash = getHash(`${poolname}${username}:${password}`, 32);
  const buffer = Buffer.from(padHex(salt) + hash, 'hex');
  return new BigInteger(getHash(buffer, 32), 16);
};

export const padHex = (hex: string): string => {
  if ('89ABCDEFabcdef'.includes(hex[0])) {
    return `00${hex}`;
  } else {
    return hex;
  }
};

export const padBufferToHex = (buffer: Buffer): string => {
  return padHex(buffer.toString('hex'));
};

export const toBuffer = (bigInt: BigInteger): Buffer => {
  const str = bigInt.toString(16);
  return Buffer.from(str, 'hex');
};

export const toBufferWithLength = (bigInt: BigInteger, length: number): Buffer => {
  let str = bigInt.toString(16);
  str = str.padStart(length * 2, '0');

  return Buffer.from(str, 'hex');
};

export const fromBuffer = (buffer: Buffer): BigInteger => {
  return new BigInteger(buffer.toString('hex'), 16);
};

export const getPoolName = (poolId: string): string => {
  const name = poolId.split('_')[1];
  assert(name, 'Invalid poolId');
  return name;
};
