import sodium from "libsodium-wrappers";
import * as tweetnacl from "tweetnacl";
import * as sealedbox from "../src";

const plainText = "test message";
const textBuffer = Buffer.from(plainText);

beforeAll(async () => {
  await sodium.ready;
});

describe("SealedBox", () => {
  describe("#seal", () => {
    it("can be opened with crypto_box_seal_open", () => {
      const keyPair = tweetnacl.box.keyPair();
      const sealed = sealedbox.seal(textBuffer, keyPair.publicKey);

      const result = sodium.crypto_box_seal_open(
        sealed,
        keyPair.publicKey,
        keyPair.secretKey
      );

      expect(textBuffer).toEqual(Buffer.from(result));
    });
  });

  describe("#open", () => {
    it("can open crypto_box_seal data", () => {
      const keyPair = sodium.crypto_box_keypair();
      const sealed = sodium.crypto_box_seal(textBuffer, keyPair.publicKey);

      const result = sealedbox.open(
        new Uint8Array(sealed),
        keyPair.publicKey,
        keyPair.privateKey
      );
      expect(textBuffer).toEqual(Buffer.from(result!));
    });

    it("can open own sealed data", () => {
      const keyPair = tweetnacl.box.keyPair();
      const sealed = sealedbox.seal(textBuffer, keyPair.publicKey);

      const result = sealedbox.open(
        sealed,
        keyPair.publicKey,
        keyPair.secretKey
      );
      expect(textBuffer).toEqual(Buffer.from(result!));
    });

    it("return null when integrity is not preserved", () => {
      const keyPair = tweetnacl.box.keyPair();
      const sealed = sealedbox.seal(textBuffer, keyPair.publicKey);
      sealed[10] = 99;

      const result = sealedbox.open(
        sealed,
        keyPair.publicKey,
        keyPair.secretKey
      );
      expect(result).toBeNull();
    });
  });
});
