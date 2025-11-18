import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import ChaCha20 from 'js-chacha20';
import { Buffer } from 'buffer';

// === CONFIG ===
const API_BASE_URL = 'http://localhost:5000/api'; // Update if needed
//const API_BASE_URL = 'https://quantumsure.onrender.com/api';

// === CRYPTO HELPERS ===
function randomBytes(length) {
  const array = new Uint8Array(length);
  crypto.getRandomValues(array);
  return Buffer.from(array);
}

async function computeMac(data, key) {
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const keyBytes = typeof key === 'string' ? new TextEncoder().encode(key) : key;
  const combined = Buffer.concat([Buffer.from(dataBytes), Buffer.from(keyBytes)]);
  const hash = await crypto.subtle.digest('SHA-256', combined);
  return Buffer.from(hash);
}

async function quantumResistantEncrypt(inputData, pubKeyB64) {
  const publicKey = Buffer.from(decode(pubKeyB64));
  const sender = new MlKem1024();
  const [ciphertext, sharedSecret] = await sender.encap(publicKey);
  const { encrypted, nonce } = postQuantumEncrypt(inputData, sharedSecret);
  const combinedData = new TextEncoder().encode(`${nonce}${encrypted}`);
  const authTag = await computeMac(combinedData, sharedSecret);
  return {
    encrypted_data: `${encode(ciphertext)}:${nonce}:${encrypted}:${encode(authTag)}`,
  };
}

async function quantumResistantDecrypt(encryptedData, privateKeyB64) {
  const [ciphertextB64, nonceB64, encryptedB64, authTagB64] = encryptedData.split(':');
  if (!ciphertextB64 || !nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted data format');
  }
  const privateKey = Buffer.from(decode(privateKeyB64));
  const recipient = new MlKem1024();
  const sharedSecret = await recipient.decap(Buffer.from(decode(ciphertextB64)), privateKey);
  return await postQuantumDecrypt(encryptedB64, nonceB64, sharedSecret, authTagB64);
}

function postQuantumEncrypt(data, key) {
  const nonce = randomBytes(12);
  const dataBytes = typeof data === 'string' ? new TextEncoder().encode(data) : data;
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(dataBytes);
  return {
    encrypted: encode(encrypted),
    nonce: encode(nonce),
  };
}

async function postQuantumDecrypt(encryptedB64, nonceB64, key, authTagB64) {
  const encrypted = Buffer.from(decode(encryptedB64));
  const nonce = Buffer.from(decode(nonceB64));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}



async function encryptPrivateKey(privateKey, masterPassword) {
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const nonce = randomBytes(12);
  const chacha = new ChaCha20(key, nonce);
  const encrypted = chacha.encrypt(Buffer.from(privateKey));
  const combinedData = new TextEncoder().encode(`${encode(nonce)}${encode(encrypted)}`);
  const authTag = await computeMac(combinedData, key);
  return `${encode(nonce)}.${encode(encrypted)}.${encode(authTag)}`;
}

async function decryptPrivateKey(encryptedPrivateKey, masterPassword) {
  const [nonceB64, encryptedB64, authTagB64] = encryptedPrivateKey.split('.');
  if (!nonceB64 || !encryptedB64 || !authTagB64) {
    throw new Error('Invalid encrypted private key format');
  }
  const key = Buffer.from(masterPassword.padEnd(32, '0').slice(0, 32));
  const combinedData = new TextEncoder().encode(`${nonceB64}${encryptedB64}`);
  const computedMac = await computeMac(combinedData, key);
  if (!computedMac.equals(Buffer.from(decode(authTagB64)))) {
    throw new Error('Invalid MAC');
  }
  const nonce = Buffer.from(decode(nonceB64));
  const encrypted = Buffer.from(decode(encryptedB64));
  const chacha = new ChaCha20(key, nonce);
  const decrypted = chacha.decrypt(encrypted);
  return new TextDecoder().decode(decrypted);
}

// === API CALLS ===

async function getMyPublicKey(apiKey) {
  const res = await fetch(`${API_BASE_URL}/qshield/public-key`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { public_key } = await res.json();
  return public_key;
}

async function getMyEpk(apiKey) {
  const res = await fetch(`${API_BASE_URL}/qshield/epk`, {
    method: 'GET',
    headers: { 'api_key': apiKey }
  });
  const { encrypted_private_key } = await res.json();
  return encrypted_private_key;
}


async function createAccount(secretPhrase, masterPassword) {
  const recipient = new MlKem1024();
  const [publicKey, privateKey] = await recipient.generateKeyPair();
  const publicKeyB64 = encode(publicKey);
  const privateKeyB64 = encode(privateKey);
  const encryptedPrivateKey = await encryptPrivateKey(privateKeyB64, masterPassword);

  const response = await fetch(`${API_BASE_URL}/qshield/create`, {
    method: 'POST',
    headers: { encrypted_private_key: encryptedPrivateKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      data: { public_key: publicKeyB64, secret_phrase: secretPhrase, url: 'none' }
    }),
  });

  if (!response.ok) throw new Error(`HTTP ${response.status}`);
  const result = await response.json();
  console.log(result);
  return result;
}




async function createEncrypted(apiKey, text) {
  const publicKey = await getMyPublicKey(apiKey);
  const { encrypted_data } = await quantumResistantEncrypt(text, publicKey);

  return encrypted_data;
}


async function createDecrypted(apiKey, encrypted_text, masterPassword) {
    const encryptedPrivateKey = await getMyEpk(apiKey);
    const privateKeyB64 = await decryptPrivateKey(encryptedPrivateKey, masterPassword);
    const password = await quantumResistantDecrypt(encrypted_text, privateKeyB64);
    return password;
}


async function createAccountF(){
    const mp = document.getElementById('mp').value;
    const sp = document.getElementById('sp').value;
    const res = await createAccount(mp, sp);
    console.log(res);
}
window.createAccountF = createAccountF;


async function testEncryptDecrypt(){
    const mp = document.getElementById('mp2').value;
    const apiKey = document.getElementById('apikey').value;
    const res1 = await createEncrypted(apiKey, "Mitochondria are the powerhouses of the cell.");
    console.log(res1);
    const res2 = await createDecrypted(apiKey, res1, mp);
    console.log(res2);
}
window.testEncryptDecrypt = testEncryptDecrypt;
