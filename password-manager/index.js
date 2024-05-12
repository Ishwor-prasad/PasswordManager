const KeyChain = require("./password-manager");
const { subtle } = require("crypto").webcrypto;
const crypto = require("crypto");
const fs = require("fs").promises;
const readline = require("readline");

const rl = readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

const storageFile = "masterKey.txt";
const KVSfile = "kvs.txt";

function ask(question) {
  return new Promise((resolve, reject) => {
    rl.question(question, (answer) => {
      resolve(answer);
    });
  });
}

async function loadKVSfromFile() {
  try {
    const content = await fs.readFile(KVSfile, "utf-8");
    const lines = content.trim().split("\n").slice(1); // Remove header line and split into individual lines
    const kvs = {};
    for (const line of lines) {
      const [key, iv, ciphertextBase64, byteLength] = line.split(","); // Split line into columns
      const ciphertext = Buffer.from(ciphertextBase64, "base64");
      kvs[key] = { iv, ciphertext, byteLength: parseInt(byteLength, 10) };
    }

    kvsdata = conversion(kvs);

    const finalConvertedKVS = convertedKVS(kvsdata);

    return finalConvertedKVS;
  } catch (error) {
    console.error("Failed to load KVS:", error.message);
    return {};
  }
}

// function conversion(kvs) {
//   const kvsdata = {};
//   for (const key in kvs) {
//     const cleanKey = key.replace(/"/g, ""); // Remove extra quotes
//     const iv = kvs[key].iv.replace(/"/g, ""); // Remove extra quotes
//     const ciphertext = kvs[key].ciphertext.buffer; // Convert Buffer to ArrayBuffer
//     console.log("ciphertext: ", ciphertext);
//     kvsdata[cleanKey] = {
//       iv,
//       ciphertext,
//       byteLength: kvs[key].byteLength,
//     };
//   }
//   return kvsdata;
// }

function conversion(input) {
  const loadedKVS = {};
  for (const key in input) {
    const iv = input[key].iv;
    const ciphertext = `<Buffer ${input[key].ciphertext.toString("hex")}>`;
    loadedKVS[key] = { iv, ciphertext };
  }
  return loadedKVS;
}

function convertedKVS(loadedKVS) {
  const convertedKVS = {};
  for (const key in loadedKVS) {
    const cleanKey = key.replace(/"/g, ""); // Remove extra quotes
    const iv = loadedKVS[key].iv.replace(/"/g, ""); // Remove extra quotes
    const ciphertextString = loadedKVS[key].ciphertext
      .replace(/^<Buffer /, "")
      .replace(/>$/, "")
      .replace(/ /g, "");
    const ciphertextBytes = ciphertextString
      .match(/.{1,2}/g)
      .map((byte) => parseInt(byte, 16)); // Convert hex string to array of bytes
    const ciphertext = new Uint8Array(ciphertextBytes).buffer; // Convert array of bytes to ArrayBuffer

    convertedKVS[cleanKey] = {
      iv,
      ciphertext,
    };
  }

  return convertedKVS;
}

async function storeKVStoFile(kvs) {
  try {
    let content = "key,iv,ciphertext,byteLength\n";
    for (const key in kvs) {
      const iv = kvs[key].iv;
      const ciphertext = Buffer.from(kvs[key].ciphertext).toString("base64");
      const byteLength = kvs[key].ciphertext.byteLength;
      content += `"${key}","${iv}","${ciphertext}",${byteLength}\n`;
    }
    await fs.writeFile(KVSfile, content);
    console.log("KVS stored successfully.");
  } catch (error) {
    console.error("Failed to store KVS:", error);
  }
}

async function loadMasterKey() {
  try {
    const keyData = await fs.readFile(storageFile);
    const importedKey = await subtle.importKey(
      "raw",
      keyData,
      { name: "AES-GCM" },
      false,
      ["encrypt", "decrypt"]
    );
    return importedKey;
  } catch (error) {
    console.error("Error loading derived key:", error.message);
    return null; // Return null if file doesn't exist or cannot be read
  }
}

// Function to load the master key from file
// async function loadMasterKey() {
//   try {
//     const keyData = await fs.readFile(storageFile, "utf-8");
//     return await subtle.importKey(
//       "raw",
//       Buffer.from(keyData, "hex"),
//       { name: "PBKDF2" },
//       false,
//       ["deriveKey"]
//     );
//   } catch (error) {
//     return null; // Return null if file doesn't exist or cannot be read
//   }
// }

// Function to store the master key to file
async function storeMasterKey(derivedKey) {
  const exportedKey = Buffer.from(await subtle.exportKey("raw", derivedKey));
  await fs.writeFile(storageFile, exportedKey);
}

async function deriveMasterKey(masterPassword) {
  const salt = crypto.randomBytes(16);
  const keyMaterial = await subtle.importKey(
    "raw",
    encode(masterPassword),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    keyMaterial,
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
}

async function main() {
  const loadKey = await loadMasterKey();
  let masterPassword;
  let derivedKey = loadKey;
  if (loadKey === null) {
    masterPassword = await ask("Enter your master password: ");
    derivedKey = await deriveMasterKey(masterPassword);
    await storeMasterKey(derivedKey);
  }

  let loadKVS = {};
  loadKVS = await loadKVSfromFile();

  const keychain = new KeyChain(derivedKey, loadKVS);

  while (true) {
    const action = await ask(
      "\n*********************************\nEnter action: \n**1 to get password **\n**2 to set password **\n**3 to remove password **\n**Write exit to exit**\n*********************************\nAction:  "
    );
    if (action === "exit") {
      console.log("Exiting...");
      await storeKVStoFile(keychain.kvs);
      process.exit(0);
    }

    switch (action) {
      case "1":
        const nameToGet = await ask(
          "\n*********************************\nEnter name to retrieve password: "
        );
        const password = await keychain.get(nameToGet);
        if (password !== null) {
          console.log(
            `Password for ${nameToGet}: ${password}\n*********************************`
          );
        } else {
          console.log(
            `No password found for ${nameToGet}.\n*********************************`
          );
        }
        break;
      case "2":
        const domainName = await ask(
          "\n*********************************\nEnter name to set password for: "
        );
        const passwordDomain = await ask("Enter password: ");
        await keychain.set(domainName, passwordDomain);
        console.log(
          `Password for ${domainName} set successfully.\n*********************************`
        );
        break;
      case "3":
        const nameToRemove = await ask(
          "\n*********************************\nEnter name to remove password for: "
        );
        const removed = await keychain.remove(nameToRemove);
        if (removed) {
          console.log(
            `Password for ${nameToRemove} removed successfully.\n*********************************`
          );
        } else {
          console.log(
            `No password found for ${nameToRemove}.\n*********************************`
          );
        }
        break;
      default:
        console.log(
          "\n*********************************\nInvalid action. Please try again.\n*********************************"
        );
        break;
    }
  }
}

main().catch(console.error);
