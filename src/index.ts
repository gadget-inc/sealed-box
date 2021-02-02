import blake from "blakejs/blake2b";
import nacl from "tweetnacl";

export const overheadLength =
  nacl.box.publicKeyLength + nacl.box.overheadLength;

export function zero(buffer: Uint8Array) {
  for (var i = 0; i < buffer.length; i++) {
    buffer[i] = 0;
  }
}

export function nonce(key1: Uint8Array, key2: Uint8Array) {
  var state = blake.blake2bInit(nacl.box.nonceLength, null);
  blake.blake2bUpdate(state, key1);
  blake.blake2bUpdate(state, key2);
  return blake.blake2bFinal(state);
}

export function open(
  sealed: Uint8Array,
  publicKey: Uint8Array,
  secretKey: Uint8Array
) {
  const ephemeralKey = sealed.subarray(0, nacl.box.publicKeyLength);
  const _nonce = nonce(ephemeralKey, publicKey);

  const boxData = sealed.subarray(nacl.box.publicKeyLength);
  return nacl.box.open(boxData, _nonce, ephemeralKey, secretKey);
}

export function seal(message: Buffer | Uint8Array, publicKey: Uint8Array) {
  const sealed = new Uint8Array(overheadLength + message.length);

  const ephemeralKey = nacl.box.keyPair();
  sealed.set(ephemeralKey.publicKey);

  const _nonce = nonce(ephemeralKey.publicKey, publicKey);
  const boxed = nacl.box(message, _nonce, publicKey, ephemeralKey.secretKey);
  sealed.set(boxed, ephemeralKey.publicKey.length);

  zero(ephemeralKey.secretKey);

  return sealed;
}
