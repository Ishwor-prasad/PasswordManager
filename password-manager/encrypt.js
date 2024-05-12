const crypto = require("crypto");
const {encode, decode}= require('./lib')
const error = require ("console");
const KeyChain = require("./password-manager");
const app = express();

class KEYCHAIN{
        constructor(key,kvs){
        this.key = key;
        this.kvs =kvs;
    }
 static async encryptvalue(value,KEY){
    const iv = crypto.randomBytes(12);
    const ciphertext = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv:Buffer.from(iv,"hex")},
        KEY,
        encode(value)
    );

    return {iv:iv.toString("hex"),ciphertext};





 }
 static async decryptvalue(ciphertext,KEY){
        const iv = crypto.randomBytes(12);
        const encryptedData = ciphertext.ciphertext;
        const decryptedData= await crypto.subtle.decrypt(
            {name:"AES_GCM",iv:Buffer.from(iv,"hex")},
            KEY,
            encryptedData
        );
        return decode(decryptedData);

    }
 static async getKey(keyData){
    //code to get retrival the key
 }

 async set(domain,password){
    const ciphertext = await KeyChain.encryptvalue(password,this.key);
    const hashedDomain= await KeyChain.computeHMAC(domain,this.key)
    this.kvs[hashedDomain]=ciphertext



 }
 async get(domain){
    const hashedDomain= await KeyChain.computeHMAC(domain,this.key)
    const ciphertext= this.kvs[hashedDomain]
    if(!ciphertext) return null;
    const plaintext= await KeyChain.decryptValue(ciphertext,this.key)
    return plaintext;

 }
 async remove(domain){
    try{
    const hashedDomain= await KeyChain.computeHMAC(domain, this.key)
    delete this.kvs[hashedDomain]
    return true;
    }catch(error){
        return false;
    }

 }

 static async computeHMAC(data, key){
    const hmac = crypto.createHash("sha256",key)
    hmac.update(data)
    return hmac.digest("hex")

 }




}
module.exports= KeyChain;
