import type { LocalKeyHandle } from './handles'
import type { KeyAlgs, SigAlgs } from '../enums'

import { ariesAskar } from '../ariesAskar'
import { KeyMethod, keyAlgFromString } from '../enums'

import { Jwk } from './Jwk'

export class Key {
  private localKeyHandle: LocalKeyHandle

  public constructor(handle: LocalKeyHandle) {
    this.localKeyHandle = handle
  }

  public static generate(algorithm: KeyAlgs, ephemeral = false) {
    return new Key(ariesAskar.keyGenerate({ algorithm, ephemeral }))
  }

  public static fromSeed({
    method = KeyMethod.None,
    algorithm,
    seed,
  }: {
    algorithm: KeyAlgs
    seed: Uint8Array
    method?: KeyMethod
  }) {
    return new Key(ariesAskar.keyFromSeed({ algorithm, method, seed }))
  }

  public static fromSecretBytes(options: { algorithm: KeyAlgs; secretKey: Uint8Array }) {
    return new Key(ariesAskar.keyFromSecretBytes(options))
  }

  public static fromPublicBytes(options: { algorithm: KeyAlgs; publicKey: Uint8Array }) {
    return new Key(ariesAskar.keyFromPublicBytes(options))
  }

  public static fromJwk(options: { jwk: Jwk }) {
    return new Key(ariesAskar.keyFromJwk(options))
  }

  public convertkey(options: { algorithm: KeyAlgs }) {
    return new Key(ariesAskar.keyConvert({ localKeyHandle: this.handle, ...options }))
  }

  public keyFromKeyExchange({ algorithm, publicKey }: { algorithm: KeyAlgs; publicKey: Key }) {
    return new Key(ariesAskar.keyFromKeyExchange({ skHandle: this.handle, pkHandle: publicKey.handle, algorithm }))
  }

  public get handle() {
    return this.localKeyHandle
  }

  public get algorithm() {
    const alg = ariesAskar.keyGetAlgorithm({ localKeyHandle: this.handle })
    return keyAlgFromString(alg)
  }

  public get ephemeral() {
    return Boolean(ariesAskar.keyGetEphemeral({ localKeyHandle: this.handle }))
  }

  public get publicBytes() {
    return ariesAskar.keyGetPublicBytes({ localKeyHandle: this.handle })
  }

  public get secretBytes() {
    return ariesAskar.keyGetSecretBytes({ localKeyHandle: this.handle })
  }

  public get jwkPublic(): Jwk {
    return Jwk.fromString(ariesAskar.keyGetJwkPublic({ localKeyHandle: this.handle, algorithm: this.algorithm }))
  }

  public get jwkSecret() {
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment, @typescript-eslint/no-unsafe-call
    const decoder = new TextDecoder()
    const secretBytes = ariesAskar.keyGetJwkSecret({ localKeyHandle: this.handle })
    // eslint-disable-next-line @typescript-eslint/no-unsafe-argument, @typescript-eslint/no-unsafe-member-access, @typescript-eslint/no-unsafe-call
    return Jwk.fromString(decoder.decode(secretBytes))
  }

  public get jwkThumbprint() {
    return ariesAskar.keyGetJwkThumbprint({ localKeyHandle: this.handle, algorithm: this.algorithm })
  }

  public get aeadParams() {
    return ariesAskar.keyAeadGetParams({ localKeyHandle: this.handle })
  }

  public get aeadRandomNonce() {
    return ariesAskar.keyAeadRandomNonce({ localKeyHandle: this.handle })
  }

  public aeadEncrypt(options: { message: Uint8Array; nonce?: Uint8Array; aad?: Uint8Array }) {
    return ariesAskar.keyAeadEncrypt({ localKeyHandle: this.handle, ...options })
  }

  public aeadDecrypt(options: { ciphertext: Uint8Array; nonce: Uint8Array; tag?: Uint8Array; aad?: Uint8Array }) {
    return ariesAskar.keyAeadDecrypt({ localKeyHandle: this.handle, ...options })
  }

  public signMessage(options: { message: Uint8Array; sigType?: SigAlgs }) {
    return ariesAskar.keySignMessage({ localKeyHandle: this.handle, ...options })
  }

  public verifySignature(options: { message: Uint8Array; signature: Uint8Array; sigType?: SigAlgs }) {
    return ariesAskar.keyVerifySignature({ localKeyHandle: this.handle, ...options })
  }

  public wrapKey({ other, nonce }: { other: Key; nonce?: Uint8Array }) {
    return ariesAskar.keyWrapKey({ localKeyHandle: this.handle, other: other.handle, nonce })
  }

  public unwrapKey(options: { algorithm: KeyAlgs; tag?: Uint8Array; ciphertext: Uint8Array; nonce?: Uint8Array }) {
    return new Key(ariesAskar.keyUnwrapKey({ localKeyHandle: this.handle, ...options }))
  }
}
