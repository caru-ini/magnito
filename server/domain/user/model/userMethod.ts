import type { AttributeType } from '@aws-sdk/client-cognito-identity-provider';
import assert from 'assert';
import type { ChangePasswordTarget, VerifyUserAttributeTarget } from 'common/types/auth';
import type { EntityId } from 'common/types/brandedId';
import type { UserEntity } from 'common/types/user';
import { genConfirmationCode } from 'domain/user/service/genConfirmationCode';
import { brandedId } from 'service/brandedId';
import { cognitoAssert } from 'service/cognitoAssert';
import { ulid } from 'ulid';
import { z } from 'zod';
import { createAttributes } from '../service/createAttributes';
import { genCredentials } from '../service/genCredentials';
import { validatePass } from '../service/validatePass';

export const userMethod = {
  create: (
    idCount: number,
    params: {
      name: string;
      password: string;
      email: string;
      userPoolId: EntityId['userPool'];
      attributes: AttributeType[] | undefined;
    },
  ): UserEntity => {
    assert(params.attributes);
    cognitoAssert(idCount === 0, 'User already exists');
    cognitoAssert(
      /^[a-z][a-z\d_-]/.test(params.name),
      "1 validation error detected: Value at 'username' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{M}\\p{S}\\p{N}\\p{P}]+",
    );
    validatePass(params.password);
    cognitoAssert(z.string().email().parse(params.email), 'Invalid email address format.');

    const now = Date.now();

    return {
      ...genCredentials({
        poolId: params.userPoolId,
        username: params.name,
        password: params.password,
      }),
      id: brandedId.user.entity.parse(ulid()),
      email: params.email,
      enabled: true,
      status: 'UNCONFIRMED',
      name: params.name,
      password: params.password,
      refreshToken: ulid(),
      userPoolId: params.userPoolId,
      confirmationCode: genConfirmationCode(),
      attributes: createAttributes(params.attributes, []),
      createdTime: now,
      updatedTime: now,
    };
  },
  confirm: (user: UserEntity, confirmationCode: string): UserEntity => {
    cognitoAssert(
      user.confirmationCode === confirmationCode,
      'Invalid verification code provided, please try again.',
    );

    return { ...user, status: 'CONFIRMED', updatedTime: Date.now() };
  },
  changePassword: (params: {
    user: UserEntity;
    req: ChangePasswordTarget['reqBody'];
  }): UserEntity => {
    cognitoAssert(
      params.user.password === params.req.PreviousPassword,
      'Incorrect username or password.',
    );
    validatePass(params.req.ProposedPassword);

    return {
      ...params.user,
      ...genCredentials({
        poolId: params.user.userPoolId,
        username: params.user.name,
        password: params.req.ProposedPassword,
      }),
      password: params.req.ProposedPassword,
      refreshToken: ulid(),
      challenge: undefined,
      updatedTime: Date.now(),
    };
  },
  forgotPassword: (user: UserEntity): UserEntity => {
    const confirmationCode = genConfirmationCode();

    return { ...user, status: 'RESET_REQUIRED', confirmationCode, updatedTime: Date.now() };
  },
  confirmForgotPassword: (params: {
    user: UserEntity;
    confirmationCode: string;
    password: string;
  }): UserEntity => {
    const { user, confirmationCode } = params;
    cognitoAssert(
      user.confirmationCode === confirmationCode,
      'Invalid verification code provided, please try again.',
    );
    validatePass(params.password);

    return {
      ...user,
      ...genCredentials({
        poolId: user.userPoolId,
        username: user.name,
        password: params.password,
      }),
      status: 'CONFIRMED',
      confirmationCode: '',
      updatedTime: Date.now(),
    };
  },
  updateAttributes: (user: UserEntity, attributes: AttributeType[] | undefined): UserEntity => {
    assert(attributes);
    const email = attributes.find((attr) => attr.Name === 'email')?.Value ?? user.email;
    const verified = user.email === email;

    return {
      ...user,
      attributes: createAttributes(attributes, user.attributes),
      status: verified ? user.status : 'UNCONFIRMED',
      confirmationCode: verified ? user.confirmationCode : genConfirmationCode(),
      email,
      updatedTime: Date.now(),
    };
  },
  verifyAttribute: (user: UserEntity, req: VerifyUserAttributeTarget['reqBody']): UserEntity => {
    assert(req.AttributeName === 'email');
    cognitoAssert(
      user.confirmationCode === req.Code,
      'Invalid verification code provided, please try again.',
    );

    return { ...user, status: 'CONFIRMED', updatedTime: Date.now() };
  },
  deleteAttributes: (user: UserEntity, attributeNames: string[] | undefined): UserEntity => {
    assert(attributeNames);

    return {
      ...user,
      attributes: user.attributes.filter((attr) => !attributeNames.includes(attr.name)),
      updatedTime: Date.now(),
    };
  },
};
