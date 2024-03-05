import { webcrypto } from "crypto";

// #############
// ### Utils ###
// #############

// Function to convert ArrayBuffer to Base64 string
function arrayBufferToBase64(buffer: ArrayBuffer): string {
  return Buffer.from(buffer).toString("base64");
}

// Function to convert Base64 string to ArrayBuffer
function base64ToArrayBuffer(base64: string): ArrayBuffer {
  var buff = Buffer.from(base64, "base64");
  return buff.buffer.slice(buff.byteOffset, buff.byteOffset + buff.byteLength);
}

// ################
// ### RSA keys ###
// ################

// Generates a pair of private / public RSA keys
type GenerateRsaKeyPair = {
  publicKey: webcrypto.CryptoKey;
  privateKey: webcrypto.CryptoKey;
};
export async function generateRsaKeyPair(): Promise<GenerateRsaKeyPair> {
  const crypto = webcrypto;

  const keyPair = await crypto.subtle.generateKey(
      {
        name: 'RSA-OAEP',
        modulusLength: 2048,
        publicExponent: new Uint8Array([0x01, 0x00, 0x01]),
        hash: 'SHA-256',
      },
      true, // extractable
      ['encrypt', 'decrypt']
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Export a crypto public key to a base64 string format


export async function exportPubKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a public key

    const publicKey = await webcrypto.subtle.exportKey('spki', key);
    return arrayBufferToBase64(publicKey);
}

// Export a crypto private key to a base64 string format
export async function exportPrvKey(
  key: webcrypto.CryptoKey | null
): Promise<string | null> {
  // TODO implement this function to return a base64 string version of a private key
    // tip: if the key is null, return null
    if (key === null) {
        return null;
    }
    const privateKey = await webcrypto.subtle.exportKey('pkcs8', key);
    return arrayBufferToBase64(privateKey);
}

// Import a base64 string public key to its native format
export async function importPubKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPubKey function to it's native crypto key object


    const publicKey = await webcrypto.subtle.importKey(
        'spki',
        base64ToArrayBuffer(strKey),
        {
            name: 'RSA-OAEP',
            hash: 'SHA-256',
        },
        true,
        ['encrypt']
    );
    return publicKey;
}

// Import a base64 string private key to its native format
export async function importPrvKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportPrvKey function to it's native crypto key object

        const privateKey = await webcrypto.subtle.importKey(
            'pkcs8',
            base64ToArrayBuffer(strKey),
            {
                name: 'RSA-OAEP',
                hash: 'SHA-256',
            },
            true,
            ['decrypt']
        );
        return privateKey;
}

// Encrypt a message using an RSA public key
export async function rsaEncrypt(
  b64Data: string,
  strPublicKey: string
): Promise<string> {
  // TODO implement this function to encrypt a base64 encoded message with a public key
  // tip: use the provided base64ToArrayBuffer function

    const publicKey = await importPubKey(strPublicKey);
    const data = base64ToArrayBuffer(b64Data);
    const encrypted = await webcrypto.subtle.encrypt(
        {
            name: 'RSA-OAEP',
        },
        publicKey,
        data
    );
    return arrayBufferToBase64(encrypted);
}

// Decrypts a message using an RSA private key
export async function rsaDecrypt(
  data: string,
  privateKey: webcrypto.CryptoKey
): Promise<string> {
  // TODO implement this function to decrypt a base64 encoded message with a private key
  // tip: use the provided base64ToArrayBuffer function
  const encrypted = base64ToArrayBuffer(data);

        const decrypted = await webcrypto.subtle.decrypt(
            {
                name: 'RSA-OAEP',
            },
            privateKey,
            encrypted
        );
        return arrayBufferToBase64(decrypted);
}

// ######################
// ### Symmetric keys ###
// ######################

// Generates a random symmetric key
export async function createRandomSymmetricKey(): Promise<webcrypto.CryptoKey> {
  // TODO implement this function using the crypto package to generate a symmetric key.
  //      the key should be used for both encryption and decryption. Make sure the
  //      keys are extractable.

  const key = await webcrypto.subtle.generateKey(
      {
        name: 'AES-CBC',
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
  );
  return key;
}

// Export a crypto symmetric key to a base64 string format
export async function exportSymKey(key: webcrypto.CryptoKey): Promise<string> {
  // TODO implement this function to return a base64 string version of a symmetric key

        const keyData = await webcrypto.subtle.exportKey('raw', key);
        return arrayBufferToBase64(keyData);
}

// Import a base64 string format to its crypto native format
export async function importSymKey(
  strKey: string
): Promise<webcrypto.CryptoKey> {
  // TODO implement this function to go back from the result of the exportSymKey function to it's native crypto key object

        const key = await webcrypto.subtle.importKey(
            'raw',

            base64ToArrayBuffer(strKey),
            {
                name: 'AES-CBC',
            },
            true,
            ['encrypt', 'decrypt']
        );
        return key;
}

// Encrypt a message using a symmetric key
export async function symEncrypt(
    // TODO implement this function to encrypt a base64 encoded message with a public key
    // tip: encode the data to a uin8array with TextEncoder
    key: webcrypto.CryptoKey,
    data: string
): Promise<string> {
  const iv = webcrypto.getRandomValues(new Uint8Array(16));
  const encrypted = await webcrypto.subtle.encrypt(
      {
        name: 'AES-CBC',
        iv: iv,
      },
      key,
      new TextEncoder().encode(data)
  );
  return arrayBufferToBase64(iv) + ':' + arrayBufferToBase64(encrypted);
}

// Decrypt a message using a symmetric key
export async function symDecrypt(
    // TODO implement this function to decrypt a base64 encoded message with a private key

    strKey: string,
    encryptedData: string
): Promise<string> {
  const key = await importSymKey(strKey);
  const parts = encryptedData.split(':');
  const iv = base64ToArrayBuffer(parts[0]);
  const encrypted = base64ToArrayBuffer(parts[1]);

  const decrypted = await webcrypto.subtle.decrypt(
      {
        name: 'AES-CBC',
        iv: iv,
      },
      key,
      encrypted
  );
  return new TextDecoder().decode(decrypted);
}
