import { MlKem1024 } from 'crystals-kyber-js';
import { encode, decode } from 'base64-arraybuffer';
import ChaCha20 from 'js-chacha20';
import { Buffer } from 'buffer';
import detectEthereumProvider from "@metamask/detect-provider";
import Web3 from "web3";
import * as ethers from "ethers";
import artifact30 from "./QshieldLeaderboardAbey.json";
import artifact50 from "./QshieldLeaderboard2.json";
import artifact_desci from "./QshieldDescivault.json";
import artifact_messenger from "./QshieldMessenger.json";

// === CONFIG ===
//const API_BASE_URL = 'http://localhost:5000/api'; // Update if needed
const API_BASE_URL = 'https://quantumsure.onrender.com/api';


//let chains = [['Beam', '4337', '0x10f1', 'Beam Mainnet', 'Beam Mainnet', 'BEAM', 'https://build.onbeam.com/rpc'], ['Abey', '179', '0xb3', 'Abey Mainnet', 'Abey Mainnet', 'ABEY', 'https://rpc.abeychain.com']];


let chains = [['Beam', '13337', '0x3419', 'Beam Testnet', 'Beam Testnet', 'BEAM', 'https://build.onbeam.com/rpc/testnet'], ['Abey', '178', '0xb2', 'Abey Testnet', 'Abey Testnet', 'tABEY', 'https://testrpc.abeychain.com']];

let chainChoice = 0;

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


async function png(){
  try {
    const res = await fetch(`${API_BASE_URL}/intuser/ping`, {
      method: 'GET'
    });
    //const { public_key } = await res.json();
    console.log("ping success");
  }
  catch (err){
    console.log("ping failed");
  }

}
window.png = png;

async function createAccountF(){
    const mp = document.getElementById('mp').value;
    const sp = document.getElementById('sp').value;
    const res = await createAccount(sp, mp);
    console.log(res);
    document.getElementById('res_sct').style.display = 'block';
    var msg = res.message;
    if (msg.includes('successfully')){
        msg = msg.concat('. API Key (please save): ').concat(res.api_key);
    }
    document.getElementById('result').textContent = msg;

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


async function getSignF(){
  const ak = document.getElementById('ak').value;
  const response = await fetch(`${API_BASE_URL}/qshield/sign`, {
    method: 'POST',
    headers: { 'api_key': ak, 'Content-Type': 'application/json'},
    body: JSON.stringify({
      data: { playerAddress: '0x8dc2f551c50F95BF9065C3cb3620611Ce97307F8', identifier: "alice.eth", score: 999 }
    }),
  });
  const { score, nonce, v, r, s } = await response.json();
  console.log(s);
}
window.getSignF = getSignF;

async function deployF1(){
  const acc_cur = localStorage.getItem("acc") || "";
    //console.log(acc_cur);
    if (acc_cur == "" || acc_cur == null){
        alert('You need to be logged in with your Beam wallet for this function.')
        return;
  }

  var chainId = parseInt(chains[chainChoice][1]);
  var cid = chains[chainChoice][2];
  var chain = chains[chainChoice][3];
  var name = chains[chainChoice][4];
  var symbol = chains[chainChoice][5];
  var rpc = chains[chainChoice][6];

  if (window.ethereum.networkVersion !== chainId) {
      try {
          await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: cid }]
          });
          console.log("changed to ".concat(name).concat(" successfully"));

      } catch (err) {
          console.log(err);
          // This error code indicates that the chain has not been added to MetaMask
          if (err.code === 4902) {
              console.log("please add ".concat(name).concat(" as a network"));
                  await window.ethereum.request({
                      method: 'wallet_addEthereumChain',
                      params: [
                          {
                              chainName: chain,
                              chainId: cid,
                              nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                              rpcUrls: [rpc]
                          }
                      ]
                  });
          }
          else {
              console.log(err);
          }
      }
  }
  const abi = artifact30;
  var bytecode = abi.data.bytecode.object;
  bytecode = bytecode.startsWith('0x') ? bytecode : '0x' + bytecode;
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi.abi, bytecode, signer);
  const contract = await factory.deploy('0x0D6a25f8dBfDE877CedA48C73EB9CEB3F39bD238');
  await contract.waitForDeployment();
  //console.log(contract.target);
  document.getElementById('res_sct2').style.display = 'block';
  var msg = "";
  if (contract.target){
    msg = "Your Smart Contract is deployed at address " + (contract.target) + '. Please check out the transaction hash on your wallet and use the Explorer for details.';
  }

    if (msg == ""){
        msg = "Smart Contract deployment failed. Please check your wallet logs for details.";
    }
    document.getElementById('result2').textContent = msg;
}
window.deployF1 = deployF1;

async function deployF2(){
  const acc_cur = localStorage.getItem("acc") || "";
    //console.log(acc_cur);
    if (acc_cur == "" || acc_cur == null){
        alert('You need to be logged in with your Beam wallet for this function.')
        return;
  }

  var chainId = parseInt(chains[chainChoice][1]);
  var cid = chains[chainChoice][2];
  var chain = chains[chainChoice][3];
  var name = chains[chainChoice][4];
  var symbol = chains[chainChoice][5];
  var rpc = chains[chainChoice][6];

  if (window.ethereum.networkVersion !== chainId) {
      try {
          await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: cid }]
          });
          console.log("changed to ".concat(name).concat(" successfully"));

      } catch (err) {
          console.log(err);
          // This error code indicates that the chain has not been added to MetaMask
          if (err.code === 4902) {
              console.log("please add ".concat(name).concat(" as a network"));
                  await window.ethereum.request({
                      method: 'wallet_addEthereumChain',
                      params: [
                          {
                              chainName: chain,
                              chainId: cid,
                              nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                              rpcUrls: [rpc]
                          }
                      ]
                  });
          }
          else {
              console.log(err);
          }
      }
  }
  const abi = artifact50;
  var bytecode = abi.data.bytecode.object;
  bytecode = bytecode.startsWith('0x') ? bytecode : '0x' + bytecode;
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi.abi, bytecode, signer);
  const contract = await factory.deploy('0x0D6a25f8dBfDE877CedA48C73EB9CEB3F39bD238');
  await contract.waitForDeployment();
  console.log(contract.target);
  //console.log(contract.target);
  document.getElementById('res_sct2').style.display = 'block';
  var msg = "";
  if (contract.target){
    msg = "Your Smart Contract is deployed at address " + (contract.target) + '. Please check out the transaction hash on your wallet and use the Explorer for details.';
  }

    if (msg == ""){
        msg = "Smart Contract deployment failed. Please check your wallet logs for details.";
    }
    document.getElementById('result2').textContent = msg;
}
window.deployF2 = deployF2;

async function deployF3(){
  const acc_cur = localStorage.getItem("acc") || "";
    //console.log(acc_cur);
    if (acc_cur == "" || acc_cur == null){
        alert('You need to be logged in with your Beam wallet for this function.')
        return;
  }

  var chainId = chains[chainChoice][1].toString();
  var cid = chains[chainChoice][2];
  var chain = chains[chainChoice][3];
  var name = chains[chainChoice][4];
  var symbol = chains[chainChoice][5];
  var rpc = chains[chainChoice][6];

  if (window.ethereum.networkVersion !== chainId) {
      try {
          await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: cid }]
          });
          console.log("changed to ".concat(name).concat(" successfully"));

      } catch (err) {
          console.log(err);
          // This error code indicates that the chain has not been added to MetaMask
          if (err.code === 4902) {
              console.log("please add ".concat(name).concat(" as a network"));
                  await window.ethereum.request({
                      method: 'wallet_addEthereumChain',
                      params: [
                          {
                              chainName: chain,
                              chainId: cid,
                              nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                              rpcUrls: [rpc]
                          }
                      ]
                  });
          }
          else {
              console.log(err);
          }
      }
  }
  const abi = artifact_desci;
  var bytecode = abi.data.bytecode.object;
  bytecode = bytecode.startsWith('0x') ? bytecode : '0x' + bytecode;
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi.abi, bytecode, signer);
  const contract = await factory.deploy('0x0D6a25f8dBfDE877CedA48C73EB9CEB3F39bD238');
  await contract.waitForDeployment();
  console.log(contract.target);
  //console.log(contract.target);
  document.getElementById('res_sct2').style.display = 'block';
  var msg = "";
  if (contract.target){
    msg = "Your Smart Contract is deployed at address " + (contract.target) + '. Please check out the transaction hash on your wallet and use the Explorer for details.';
  }

    if (msg == ""){
        msg = "Smart Contract deployment failed. Please check your wallet logs for details.";
    }
    document.getElementById('result2').textContent = msg;
}
window.deployF3 = deployF3;


async function deployF4(){
  const acc_cur = localStorage.getItem("acc") || "";
    //console.log(acc_cur);
    if (acc_cur == "" || acc_cur == null){
        alert('You need to be logged in with your Beam wallet for this function.')
        return;
  }

  var chainId = chains[chainChoice][1].toString();
  var cid = chains[chainChoice][2];
  var chain = chains[chainChoice][3];
  var name = chains[chainChoice][4];
  var symbol = chains[chainChoice][5];
  var rpc = chains[chainChoice][6];

  if (window.ethereum.networkVersion !== chainId) {
      try {
          await window.ethereum.request({
              method: 'wallet_switchEthereumChain',
              params: [{ chainId: cid }]
          });
          console.log("changed to ".concat(name).concat(" successfully"));

      } catch (err) {
          console.log(err);
          // This error code indicates that the chain has not been added to MetaMask
          if (err.code === 4902) {
              console.log("please add ".concat(name).concat(" as a network"));
                  await window.ethereum.request({
                      method: 'wallet_addEthereumChain',
                      params: [
                          {
                              chainName: chain,
                              chainId: cid,
                              nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                              rpcUrls: [rpc]
                          }
                      ]
                  });
          }
          else {
              console.log(err);
          }
      }
  }
  const abi = artifact_messenger;
  var bytecode = abi.data.bytecode.object;
  bytecode = bytecode.startsWith('0x') ? bytecode : '0x' + bytecode;
  const provider = new ethers.BrowserProvider(window.ethereum);
  await provider.send("eth_requestAccounts", []);
  const signer = await provider.getSigner();

  const factory = new ethers.ContractFactory(abi.abi, bytecode, signer);
  const contract = await factory.deploy('0x0D6a25f8dBfDE877CedA48C73EB9CEB3F39bD238');
  await contract.waitForDeployment();
  console.log(contract.target);
  //console.log(contract.target);
  document.getElementById('res_sct2').style.display = 'block';
  var msg = "";
  if (contract.target){
    msg = "Your Smart Contract is deployed at address " + (contract.target) + '. Please check out the transaction hash on your wallet and use the Explorer for details.';
  }

    if (msg == ""){
        msg = "Smart Contract deployment failed. Please check your wallet logs for details.";
    }
    document.getElementById('result2').textContent = msg;
}
window.deployF4 = deployF4;


async function loadDeploy(){
  const acc_cur = localStorage.getItem("acc") || "";
        if (acc_cur != "" && acc_cur != null){
            document.getElementById("login-status").textContent = (acc_cur.toString().slice(0,8)).concat('..(Logout)');
        }

  if (chainChoice == 1){
    document.getElementById('c1').style.backgroundColor = "#222222";
    document.getElementById('c1').style.padding = "5px";
    document.getElementById('c1').style.height = "60px";
  }
  else {
    document.getElementById('c0').style.backgroundColor = "#222222";
    document.getElementById('c0').style.padding = "5px";
    document.getElementById('c0').style.height = "60px";
  }
}
window.loadDeploy = loadDeploy;

// metamask

async function connectOrDisconnect() {
    const acc_cur = localStorage.getItem("acc") || "";
    console.log(acc_cur);
    if (acc_cur != "" && acc_cur != null){
        localStorage.setItem("acc","");
        document.getElementById("login-status").textContent = "Login";
        return;
    }

    console.log(chains);
    var chainId = chains[chainChoice][1].toString();
    var cid = chains[chainChoice][2];
    var chain = chains[chainChoice][3];
    var name = chains[chainChoice][4];
    var symbol = chains[chainChoice][5];
    var rpc = chains[chainChoice][6];

    const provider = await detectEthereumProvider()
    console.log(window.ethereum);
    if (provider && provider === window.ethereum) {
        console.log("MetaMask is available!");

        console.log(window.ethereum.networkVersion);
        if (window.ethereum.networkVersion !== chainId) {
            try {
                await window.ethereum.request({
                    method: 'wallet_switchEthereumChain',
                    params: [{ chainId: cid }]
                });
                console.log("changed to ".concat(name).concat(" successfully"));

            } catch (err) {
                console.log(err);
                // This error code indicates that the chain has not been added to MetaMask
                if (err.code === 4902) {
                    console.log("please add ".concat(name).concat(" as a network"));
                        await window.ethereum.request({
                            method: 'wallet_addEthereumChain',
                            params: [
                                {
                                    chainName: chain,
                                    chainId: cid,
                                    nativeCurrency: { name: name, decimals: 18, symbol: symbol },
                                    rpcUrls: [rpc]
                                }
                            ]
                        });
                }
                else {
                    console.log(err);
                }
            }
        }
        await startApp(provider);
    } else {
        console.log("Please install MetaMask!")
    }



}
window.connectOrDisconnect = connectOrDisconnect;


async function startApp(provider) {
  if (provider !== window.ethereum) {
    console.error("Do you have multiple wallets installed?")
  }
  else {
    const accounts = await window.ethereum
    .request({ method: "eth_requestAccounts" })
    .catch((err) => {
      if (err.code === 4001) {
        console.log("Please connect to MetaMask.")
      } else {
        console.error(err)
      }
    })
    console.log("hi");
  const account = accounts[0];
  var web3 = new Web3(window.ethereum);
  const bal = await web3.eth.getBalance(account);
  //console.log("hi");
  console.log(bal);
  console.log(account);
  localStorage.setItem("acc",account.toString());
  document.getElementById("login-status").textContent = (account.toString().slice(0,8)).concat('..(Logout)');

  }
}

async function chainIs(k){
  console.log('hi');
  chainChoice = k;
  if (k == 1){
    document.getElementById('c1').style.backgroundColor = "#222222";
    document.getElementById('c1').style.padding = "5px";
    document.getElementById('c1').style.height = "60px";
    document.getElementById('c0').style.backgroundColor = "#0a0a1a";
    document.getElementById('c0').style.padding = "0px";
    document.getElementById('c0').style.height = "50px";
  }
  else {
    document.getElementById('c0').style.backgroundColor = "#222222";
    document.getElementById('c0').style.padding = "5px";
    document.getElementById('c0').style.height = "60px";
    document.getElementById('c1').style.backgroundColor = "#0a0a1a";
    document.getElementById('c1').style.padding = "0px";
    document.getElementById('c1').style.height = "50px";
  }
}
window.chainIs = chainIs;


async function toPlan(){
  window.location.href = './plans.html';
}
window.toPlan = toPlan;
