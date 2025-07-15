let ww_version = "03";
self.addEventListener("message", handleMessage);
let eh = new ww_encryption_handler();
let active_mp_buff = null;
let active_pk_buff = null;
let active_ecdh_priv_key = null;
let active_ecdh_pub_key = null;
let shared_ecdh_pub_key = null;
let secp_h;
let kh = new keccak_handler();
let bh = new buffer_helper();
let active_prf_key = null;
let active_prf_buff = null;
let active_seed = null;
let active_hkdf = null;
let active_det_ecdh_pub_buff = null;
let salt_byte_len = 16;
let salt_hex_len = 32;
let misc_slice = 32;
let det_ecdh_h = new determineEcdh();
function handleMessage(msg_event) {
    var msg_type = msg_event.data.msg_type;
    switch (msg_type) {
    case "get_version":
        self.postMessage(ww_version);
        break;
    case "prf_to_key":
        buffToHkdf(msg_event.data.prf_buff, function(ret) {
            active_prf_key = ret;
            active_prf_buff = msg_event.data.prf_buff;
            self.postMessage(null);
        });
        break;
    case "set_seed":
        generateNewSeed(msg_event.data.seed_name, function(seed) {
            active_seed = seed;
            seedToHkdf(seed, function(hkdf) {
                active_hkdf = hkdf;
                self.postMessage(null);
                genDetEcdh(active_seed);
            });
        });
        break;
    case "get_det_public_ecdh":
        self.postMessage(active_det_ecdh_pub_buff);
        break;
    case "gen_seed_pk":
        var key = active_hkdf;
        generateAesFromHkdf(active_hkdf, function(ret) {
            var salt1 = ret.salt;
            var aes_key = ret.aes_key;
        });
        break;
    case "new_enc":
        var key = active_hkdf;
        var msg_buff = msg_event.data.msg_buff;
        generateAesFromHkdf(key, null, function(ret) {
            var key_salt = ret.salt;
            var aes_key = ret.aes_key;
            eh.encrypt(aes_key, msg_buff, key_salt, function(encrypted_buff) {
                self.postMessage({
                    encrypted_buff,
                    salt: key_salt
                }, [encrypted_buff, key_salt]);
            });
        });
        break;
    case "new_dec":
        var key = active_hkdf;
        var msg_buff = msg_event.data.msg_buff;
        var key_salt = msg_buff.slice(0, salt_byte_len);
        generateAesFromHkdf(key, key_salt, function(ret) {
            var aes_key = ret.aes_key;
            eh.noDecodeDecrypt(aes_key, msg_buff.slice(salt_byte_len), key_salt, function(decrypted_buff) {
                if (decrypted_buff === null)
                    self.postMessage(null);
                else
                    self.postMessage({
                        decrypted_buff
                    }, [decrypted_buff]);
            });
        });
        break;
    case "set_shared_pub":
        eh.importEcdhPub(msg_event.data.pub_buff, function(key) {
            shared_ecdh_pub_key = key;
            self.postMessage(true);
        });
        break;
    case "shared_ecdh_enc":
        var msg_buff = msg_event.data.msg_buff;
        eh.deriveEcdhKey(active_ecdh_priv_key, shared_ecdh_pub_key, function(derived_key) {
            var iv = self.crypto.getRandomValues(new Uint8Array(salt_byte_len));
            iv = iv.buffer;
            eh.encrypt(derived_key, msg_buff, iv, function(encrypted_buff) {
                var salt = iv;
                self.postMessage({
                    encrypted_buff,
                    salt
                }, [encrypted_buff, salt]);
            });
        });
        break;
    case "shared_ecdh_dec":
        var msg_buff = msg_event.data.msg_buff;
        var key_salt = msg_buff.slice(0, salt_byte_len);
        msg_buff = msg_buff.slice(salt_byte_len);
        eh.importEcdhPub(msg_event.data.pub_buff, function(shared_pub) {
            eh.deriveEcdhKey(active_ecdh_priv_key, shared_pub, function(derived_key) {
                eh.noDecodeDecrypt(derived_key, msg_buff, key_salt, function(decrypted_buff) {
                    if (decrypted_buff === null)
                        self.postMessage(null);
                    else
                        self.postMessage({
                            decrypted_buff
                        }, [decrypted_buff]);
                });
            });
        });
        break;
    }
    function genDetEcdh(seed) {
        var ret1 = det_ecdh_h.generateKeyPair(seed);
        det_ecdh_h.convertKeys(ret1.privateKey, ret1.publicKey, function(result) {
            active_det_ecdh_pub_buff = result.publicKey.rawBuffer;
            active_ecdh_priv_key = result.privateKey.key;
            active_ecdh_pub_key = result.publicKey.key;
        });
    }
    function buffToHkdf(prf_buff, cb) {
        self.crypto.subtle.importKey("raw", prf_buff, {
            name: "HKDF"
        }, false, ["deriveKey", "deriveBits"]).then(cb);
    }
    function generateNewSeed(seed_name="", cb) {
        var sliced_buff = active_prf_buff.slice(0, misc_slice);
        let salt = kh.strict_hex_keccak256(bh.bufferToHex(sliced_buff) + seed_name);
        let info = new TextEncoder().encode("filekey pk seed: " + salt);
        keyToSeed(active_prf_key, bh.hexToArrayBuffer(salt), info, function(seed) {
            cb(seed);
        });
    }
    function seedToHkdf(seed, cb) {
        buffToHkdf(seed, function(ret) {
            var qq = 222;
            cb(ret);
        });
    }
    function keyToSeed(imported_key, salt, info, cb) {
        self.crypto.subtle.deriveBits({
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: info,
        }, imported_key, 512).then(callbackWithSeed);
        function callbackWithSeed(seed_buff) {
            cb(seed_buff);
        }
    }
    function generateAesFromHkdf(hkdf, known_salt=null, cb) {
        let salt = (known_salt === null) ? (self.crypto.getRandomValues(new Uint8Array(salt_byte_len))).buffer : known_salt;
        var alg = {
            name: "HKDF",
            hash: "SHA-256",
            salt: salt,
            info: new Uint8Array([]),
        };
        var derived_alg = {
            name: "AES-GCM",
            length: 256
        };
        self.crypto.subtle.deriveKey(alg, hkdf, derived_alg, true, ["encrypt", "decrypt"]).then(function(aes_key) {
            cb({
                aes_key,
                salt
            });
        });
    }
    function checkForProperty(prop) {
        return (prop === "" || prop === null || prop === undefined) ? false : true;
    }
}
function ww_encryption_handler() {
    this.encrypt = encrypt;
    function encrypt(key, plaintext, iv, cb, aad="") {
        var alg_obj = {
            name: "AES-GCM",
            iv
        };
        if (aad != "")
            alg_obj.additionalData = aad;
        self.crypto.subtle.encrypt(alg_obj, key, plaintext).then( (encrpyted_stuff) => {
            cb(encrpyted_stuff);
        }
        );
    }
    this.noDecodeDecrypt = noDecodeDecrypt;
    function noDecodeDecrypt(key, ciphertext, iv, cb, aad="") {
        var alg_obj = {
            name: "AES-GCM",
            iv
        };
        if (aad != "")
            alg_obj.additionalData = aad;
        self.crypto.subtle.decrypt(alg_obj, key, ciphertext).then( (decrpyted_stuff) => {
            cb(decrpyted_stuff);
        }
        ).catch(function(e) {
            cb(null)
        });
    }
    this.hexToArrayBuffer = hexToArrayBuffer;
    function hexToArrayBuffer(hex_str, buffer_type=null) {
        const regex = new RegExp(/0x/i);
        if (regex.test(hex_str.substring(0, 2)))
            hex_str = hex_str.substring(2);
        var ret = [];
        for (var i = 0; i < hex_str.length / 2; i++) {
            var x = i * 2;
            const n = parseInt(hex_str.substr(x, 2), 16);
            ret.push(n);
        }
        if (buffer_type)
            return new buffer_type(ret);
        else
            return ret;
    }
    this.deriveEcdhKey = deriveEcdhKey;
    function deriveEcdhKey(privateKey, publicKey, callback) {
        self.crypto.subtle.deriveKey({
            name: "ECDH",
            public: publicKey,
        }, privateKey, {
            name: "AES-GCM",
            length: 256,
        }, true, ["encrypt", "decrypt"]).then(callback);
    }
    this.importEcdhPub = importEcdhPub;
    function importEcdhPub(pub_buff, cb) {
        crypto.subtle.importKey("raw", pub_buff, {
            name: "ECDH",
            namedCurve: "P-521"
        }, true, []).then(cb);
    }
}
function buffer_helper() {
    this.convertBufferType = convertBufferType;
    this.bufferPush = bufferPush;
    this.getBufferTypedArrayConstructor = getBufferTypedArrayConstructor;
    this.bufferToHex = bufferToHex;
    this.hexStringToHexNumber = hexStringToHexNumber;
    this.hexToArrayBuffer = hexToArrayBuffer;
    function convertBufferType(source_buff, output_type) {
        const buffer = new ArrayBuffer(inputBuffer.length);
        var source_buff_type = getBufferTypedArrayConstructor(Object.prototype.toString.call(source_buff));
        const source_buff_view = new source_buff_type(buffer);
        source_buff_view.set(inputBuffer);
        return new output_type(buffer);
    }
    function bufferPush(source_buff, new_values) {
        var source_buff_type = getBufferTypedArrayConstructor(Object.prototype.toString.call(source_buff));
        var new_ab = new source_buff_type(source_buff.length + 1);
        new_ab.set(source_buff, 0);
        new_ab[new_ab.length - 1] = new_values;
        return new_ab;
    }
    function getBufferTypedArrayConstructor(tag) {
        var type_name = tag.substring(8, tag.length - 1);
        var window_global = Function('return this')();
        var constructor = window_global[type_name];
        if (constructor && typeof constructor === 'function')
            return constructor;
        else
            throw new TypeError("Invalid typed array type tag: " + tag);
    }
    function bufferToHex(buffer) {
        return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, "0")).join("");
    }
    function hexStringToHexNumber(hex_str) {
        if (new RegExp(/0x/i).test(hex_str.substring(0, 2)))
            return hex_str.substring(2);
        else
            return hex_str;
    }
    function hexToArrayBuffer(hex_str, buffer_type=null) {
        hex_str = hexStringToHexNumber(hex_str);
        var ret = [];
        for (var i = 0; i < hex_str.length / 2; i++) {
            var x = i * 2;
            const n = parseInt(hex_str.substr(x, 2), 16);
            ret.push(n);
        }
        if (buffer_type)
            return new buffer_type(ret);
        else
            return new Uint8Array(ret).buffer;
    }
}
function keccak_handler() {
    var HEX_CHARS = '0123456789abcdef'.split('');
    var KECCAK_PADDING = [1, 256, 65536, 16777216];
    var SHIFT = [0, 8, 16, 24];
    var RC = [1, 0, 32898, 0, 32906, 2147483648, 2147516416, 2147483648, 32907, 0, 2147483649, 0, 2147516545, 2147483648, 32777, 2147483648, 138, 0, 136, 0, 2147516425, 0, 2147483658, 0, 2147516555, 0, 139, 2147483648, 32905, 2147483648, 32771, 2147483648, 32770, 2147483648, 128, 2147483648, 32778, 0, 2147483658, 2147483648, 2147516545, 2147483648, 32896, 2147483648, 2147483649, 0, 2147516424, 2147483648];
    this.keccak256 = keccak256;
    function keccak256(hex_str) {
        return lazy_keccak(256, hex_str);
    }
    this.strict_hex_keccak256 = strict_hex_keccak256;
    function strict_hex_keccak256(hex_str) {
        return strict_hex_keccak(256, hex_str);
    }
    this.str_keccak256 = str_keccak256;
    function str_keccak256(str) {
        return str_keccak(256, str);
    }
    function Keccak(bits) {
        return {
            blocks: [],
            reset: true,
            block: 0,
            start: 0,
            blockCount: 1600 - (bits << 1) >> 5,
            outputBlocks: bits >> 5,
            s: function(s) {
                return [].concat(s, s, s, s, s);
            }([0, 0, 0, 0, 0, 0, 0, 0, 0, 0])
        };
    }
    ;var update = function update(state, message) {
        var length = message.length, blocks = state.blocks, byteCount = state.blockCount << 2, blockCount = state.blockCount, outputBlocks = state.outputBlocks, s = state.s, index = 0, i, code;
        while (index < length) {
            if (state.reset) {
                state.reset = false;
                blocks[0] = state.block;
                for (i = 1; i < blockCount + 1; ++i)
                    blocks[i] = 0;
            }
            for (i = state.start; index < length && i < byteCount; ++index)
                blocks[i >> 2] |= message[index] << SHIFT[i++ & 3];
            state.lastByteIndex = i;
            if (i >= byteCount) {
                state.start = i - byteCount;
                state.block = blocks[blockCount];
                for (i = 0; i < blockCount; ++i)
                    s[i] ^= blocks[i];
                f(s);
                state.reset = true;
            } else
                state.start = i;
        }
        i = state.lastByteIndex;
        blocks[i >> 2] |= KECCAK_PADDING[i & 3];
        if (state.lastByteIndex === byteCount) {
            blocks[0] = blocks[blockCount];
            for (i = 1; i < blockCount + 1; ++i)
                blocks[i] = 0;
        }
        blocks[blockCount - 1] |= 0x80000000;
        for (i = 0; i < blockCount; ++i)
            s[i] ^= blocks[i];
        f(s);
        var hex = '', i = 0, j = 0, block;
        while (j < outputBlocks) {
            for (i = 0; i < blockCount && j < outputBlocks; ++i,
            ++j) {
                block = s[i];
                hex += HEX_CHARS[block >> 4 & 0x0F] + HEX_CHARS[block & 0x0F] + HEX_CHARS[block >> 12 & 0x0F] + HEX_CHARS[block >> 8 & 0x0F] + HEX_CHARS[block >> 20 & 0x0F] + HEX_CHARS[block >> 16 & 0x0F] + HEX_CHARS[block >> 28 & 0x0F] + HEX_CHARS[block >> 24 & 0x0F];
            }
            if (j % blockCount === 0) {
                f(s);
                i = 0;
            }
        }
        return "0x" + hex;
    };
    var f = function f(s) {
        var h, l, n, c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24, b25, b26, b27, b28, b29, b30, b31, b32, b33, b34, b35, b36, b37, b38, b39, b40, b41, b42, b43, b44, b45, b46, b47, b48, b49;
        for (n = 0; n < 48; n += 2) {
            c0 = s[0] ^ s[10] ^ s[20] ^ s[30] ^ s[40];
            c1 = s[1] ^ s[11] ^ s[21] ^ s[31] ^ s[41];
            c2 = s[2] ^ s[12] ^ s[22] ^ s[32] ^ s[42];
            c3 = s[3] ^ s[13] ^ s[23] ^ s[33] ^ s[43];
            c4 = s[4] ^ s[14] ^ s[24] ^ s[34] ^ s[44];
            c5 = s[5] ^ s[15] ^ s[25] ^ s[35] ^ s[45];
            c6 = s[6] ^ s[16] ^ s[26] ^ s[36] ^ s[46];
            c7 = s[7] ^ s[17] ^ s[27] ^ s[37] ^ s[47];
            c8 = s[8] ^ s[18] ^ s[28] ^ s[38] ^ s[48];
            c9 = s[9] ^ s[19] ^ s[29] ^ s[39] ^ s[49];
            h = c8 ^ (c2 << 1 | c3 >>> 31);
            l = c9 ^ (c3 << 1 | c2 >>> 31);
            s[0] ^= h;
            s[1] ^= l;
            s[10] ^= h;
            s[11] ^= l;
            s[20] ^= h;
            s[21] ^= l;
            s[30] ^= h;
            s[31] ^= l;
            s[40] ^= h;
            s[41] ^= l;
            h = c0 ^ (c4 << 1 | c5 >>> 31);
            l = c1 ^ (c5 << 1 | c4 >>> 31);
            s[2] ^= h;
            s[3] ^= l;
            s[12] ^= h;
            s[13] ^= l;
            s[22] ^= h;
            s[23] ^= l;
            s[32] ^= h;
            s[33] ^= l;
            s[42] ^= h;
            s[43] ^= l;
            h = c2 ^ (c6 << 1 | c7 >>> 31);
            l = c3 ^ (c7 << 1 | c6 >>> 31);
            s[4] ^= h;
            s[5] ^= l;
            s[14] ^= h;
            s[15] ^= l;
            s[24] ^= h;
            s[25] ^= l;
            s[34] ^= h;
            s[35] ^= l;
            s[44] ^= h;
            s[45] ^= l;
            h = c4 ^ (c8 << 1 | c9 >>> 31);
            l = c5 ^ (c9 << 1 | c8 >>> 31);
            s[6] ^= h;
            s[7] ^= l;
            s[16] ^= h;
            s[17] ^= l;
            s[26] ^= h;
            s[27] ^= l;
            s[36] ^= h;
            s[37] ^= l;
            s[46] ^= h;
            s[47] ^= l;
            h = c6 ^ (c0 << 1 | c1 >>> 31);
            l = c7 ^ (c1 << 1 | c0 >>> 31);
            s[8] ^= h;
            s[9] ^= l;
            s[18] ^= h;
            s[19] ^= l;
            s[28] ^= h;
            s[29] ^= l;
            s[38] ^= h;
            s[39] ^= l;
            s[48] ^= h;
            s[49] ^= l;
            b0 = s[0];
            b1 = s[1];
            b32 = s[11] << 4 | s[10] >>> 28;
            b33 = s[10] << 4 | s[11] >>> 28;
            b14 = s[20] << 3 | s[21] >>> 29;
            b15 = s[21] << 3 | s[20] >>> 29;
            b46 = s[31] << 9 | s[30] >>> 23;
            b47 = s[30] << 9 | s[31] >>> 23;
            b28 = s[40] << 18 | s[41] >>> 14;
            b29 = s[41] << 18 | s[40] >>> 14;
            b20 = s[2] << 1 | s[3] >>> 31;
            b21 = s[3] << 1 | s[2] >>> 31;
            b2 = s[13] << 12 | s[12] >>> 20;
            b3 = s[12] << 12 | s[13] >>> 20;
            b34 = s[22] << 10 | s[23] >>> 22;
            b35 = s[23] << 10 | s[22] >>> 22;
            b16 = s[33] << 13 | s[32] >>> 19;
            b17 = s[32] << 13 | s[33] >>> 19;
            b48 = s[42] << 2 | s[43] >>> 30;
            b49 = s[43] << 2 | s[42] >>> 30;
            b40 = s[5] << 30 | s[4] >>> 2;
            b41 = s[4] << 30 | s[5] >>> 2;
            b22 = s[14] << 6 | s[15] >>> 26;
            b23 = s[15] << 6 | s[14] >>> 26;
            b4 = s[25] << 11 | s[24] >>> 21;
            b5 = s[24] << 11 | s[25] >>> 21;
            b36 = s[34] << 15 | s[35] >>> 17;
            b37 = s[35] << 15 | s[34] >>> 17;
            b18 = s[45] << 29 | s[44] >>> 3;
            b19 = s[44] << 29 | s[45] >>> 3;
            b10 = s[6] << 28 | s[7] >>> 4;
            b11 = s[7] << 28 | s[6] >>> 4;
            b42 = s[17] << 23 | s[16] >>> 9;
            b43 = s[16] << 23 | s[17] >>> 9;
            b24 = s[26] << 25 | s[27] >>> 7;
            b25 = s[27] << 25 | s[26] >>> 7;
            b6 = s[36] << 21 | s[37] >>> 11;
            b7 = s[37] << 21 | s[36] >>> 11;
            b38 = s[47] << 24 | s[46] >>> 8;
            b39 = s[46] << 24 | s[47] >>> 8;
            b30 = s[8] << 27 | s[9] >>> 5;
            b31 = s[9] << 27 | s[8] >>> 5;
            b12 = s[18] << 20 | s[19] >>> 12;
            b13 = s[19] << 20 | s[18] >>> 12;
            b44 = s[29] << 7 | s[28] >>> 25;
            b45 = s[28] << 7 | s[29] >>> 25;
            b26 = s[38] << 8 | s[39] >>> 24;
            b27 = s[39] << 8 | s[38] >>> 24;
            b8 = s[48] << 14 | s[49] >>> 18;
            b9 = s[49] << 14 | s[48] >>> 18;
            s[0] = b0 ^ ~b2 & b4;
            s[1] = b1 ^ ~b3 & b5;
            s[10] = b10 ^ ~b12 & b14;
            s[11] = b11 ^ ~b13 & b15;
            s[20] = b20 ^ ~b22 & b24;
            s[21] = b21 ^ ~b23 & b25;
            s[30] = b30 ^ ~b32 & b34;
            s[31] = b31 ^ ~b33 & b35;
            s[40] = b40 ^ ~b42 & b44;
            s[41] = b41 ^ ~b43 & b45;
            s[2] = b2 ^ ~b4 & b6;
            s[3] = b3 ^ ~b5 & b7;
            s[12] = b12 ^ ~b14 & b16;
            s[13] = b13 ^ ~b15 & b17;
            s[22] = b22 ^ ~b24 & b26;
            s[23] = b23 ^ ~b25 & b27;
            s[32] = b32 ^ ~b34 & b36;
            s[33] = b33 ^ ~b35 & b37;
            s[42] = b42 ^ ~b44 & b46;
            s[43] = b43 ^ ~b45 & b47;
            s[4] = b4 ^ ~b6 & b8;
            s[5] = b5 ^ ~b7 & b9;
            s[14] = b14 ^ ~b16 & b18;
            s[15] = b15 ^ ~b17 & b19;
            s[24] = b24 ^ ~b26 & b28;
            s[25] = b25 ^ ~b27 & b29;
            s[34] = b34 ^ ~b36 & b38;
            s[35] = b35 ^ ~b37 & b39;
            s[44] = b44 ^ ~b46 & b48;
            s[45] = b45 ^ ~b47 & b49;
            s[6] = b6 ^ ~b8 & b0;
            s[7] = b7 ^ ~b9 & b1;
            s[16] = b16 ^ ~b18 & b10;
            s[17] = b17 ^ ~b19 & b11;
            s[26] = b26 ^ ~b28 & b20;
            s[27] = b27 ^ ~b29 & b21;
            s[36] = b36 ^ ~b38 & b30;
            s[37] = b37 ^ ~b39 & b31;
            s[46] = b46 ^ ~b48 & b40;
            s[47] = b47 ^ ~b49 & b41;
            s[8] = b8 ^ ~b0 & b2;
            s[9] = b9 ^ ~b1 & b3;
            s[18] = b18 ^ ~b10 & b12;
            s[19] = b19 ^ ~b11 & b13;
            s[28] = b28 ^ ~b20 & b22;
            s[29] = b29 ^ ~b21 & b23;
            s[38] = b38 ^ ~b30 & b32;
            s[39] = b39 ^ ~b31 & b33;
            s[48] = b48 ^ ~b40 & b42;
            s[49] = b49 ^ ~b41 & b43;
            s[0] ^= RC[n];
            s[1] ^= RC[n + 1];
        }
    };
    function strict_hex_keccak(bits, hex) {
        if (hex.length % 2 != 0)
            return null;
        if (hex.slice(0, 2) == "0x")
            hex = hex.slice(2);
        var msg = [];
        for (var i = 0; i < hex.length; i += 2) {
            var new_str = hex.slice(i, i + 2);
            new_str = parseInt(new_str, 16);
            if (new_str > 255)
                return str_keccak(bits, hex);
            msg.push(new_str);
        }
        return keccak(bits, msg);
    }
    function lazy_keccak(bits, hex) {
        if (hex.length % 2 != 0)
            return str_keccak(bits, hex);
        if (hex.slice(0, 2) == "0x")
            hex = hex.slice(2);
        var msg = [];
        for (var i = 0; i < hex.length; i += 2) {
            var new_str = hex.slice(i, i + 2);
            new_str = parseInt(new_str, 16);
            if (isNaN(new_str) || new_str > 255)
                return str_keccak(bits, hex);
            msg.push(new_str);
        }
        return keccak(bits, msg);
    }
    function str_keccak(bits, str) {
        var text_encoder = new TextEncoder();
        var msg = [];
        for (var i = 0; i < str.length; i++) {
            var new_str = str.slice(i, i + 1);
            new_str = text_encoder.encode(new_str);
            msg.push(new_str);
        }
        return keccak(bits, msg);
    }
    function keccak(bits, hex) {
        return update(Keccak(bits, bits), hex);
    }
}
function determineEcdh() {
    const P521 = {
        P: BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"),
        A: BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC"),
        B: BigInt("0x051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00"),
        GX: BigInt("0xC6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66"),
        GY: BigInt("0x11839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650"),
        N: BigInt("0x1FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409")
    };
    function modAdd(a, b, m) {
        return ((a % m) + (b % m)) % m;
    }
    function modSub(a, b, m) {
        return ((a % m) - (b % m) + m) % m;
    }
    function modMul(a, b, m) {
        return ((a % m) * (b % m)) % m;
    }
    function modInv(a, m) {
        function egcd(a, b) {
            if (a === BigInt(0))
                return [b, BigInt(0), BigInt(1)];
            const [g,x,y] = egcd(b % a, a);
            return [g, y - (b / a) * x, x];
        }
        const [g,x,_] = egcd(a, m);
        if (g !== BigInt(1))
            throw new Error("Modular inverse does not exist");
        return ((x % m) + m) % m;
    }
    function isOnCurve(point) {
        if (point === null)
            return true;
        const {x, y} = point;
        const left = modMul(y, y, P521.P);
        const x3 = modMul(modMul(x, x, P521.P), x, P521.P);
        const ax = modMul(P521.A, x, P521.P);
        const right = modAdd(modAdd(x3, ax, P521.P), P521.B, P521.P);
        return left === right;
    }
    function pointAdd(P1, P2) {
        if (P1 === null)
            return P2;
        if (P2 === null)
            return P1;
        if (P1.x === P2.x) {
            if (P1.y === P2.y) {
                return pointDouble(P1);
            }
            return null;
        }
        const slope = modMul(modSub(P2.y, P1.y, P521.P), modInv(modSub(P2.x, P1.x, P521.P), P521.P), P521.P);
        const x3 = modSub(modSub(modMul(slope, slope, P521.P), P1.x, P521.P), P2.x, P521.P);
        const y3 = modSub(modMul(slope, modSub(P1.x, x3, P521.P), P521.P), P1.y, P521.P);
        const result = {
            x: x3,
            y: y3
        };
        if (!isOnCurve(result))
            throw new Error("Point addition resulted in invalid point");
        return result;
    }
    function pointDouble(P) {
        if (P === null)
            return null;
        if (P.y === BigInt(0))
            return null;
        const slope = modMul(modAdd(modMul(BigInt(3), modMul(P.x, P.x, P521.P), P521.P), P521.A, P521.P), modInv(modMul(BigInt(2), P.y, P521.P), P521.P), P521.P);
        const x3 = modSub(modMul(slope, slope, P521.P), modMul(BigInt(2), P.x, P521.P), P521.P);
        const y3 = modSub(modMul(slope, modSub(P.x, x3, P521.P), P521.P), P.y, P521.P);
        const result = {
            x: x3,
            y: y3
        };
        if (!isOnCurve(result))
            throw new Error("Point doubling resulted in invalid point");
        return result;
    }
    function scalarMul(k, P) {
        if (k === BigInt(0))
            return null;
        if (P === null)
            return null;
        let r0 = null;
        let r1 = P;
        const bits = k.toString(2).padStart(521, '0');
        for (let i = 0; i < bits.length; i++) {
            if (bits[i] === '0') {
                r1 = pointAdd(r0, r1);
                r0 = pointDouble(r0);
            } else {
                r0 = pointAdd(r0, r1);
                r1 = pointDouble(r1);
            }
        }
        return r0;
    }
    this.generateKeyPair = generateKeyPair;
    function generateKeyPair(seed) {
        if (!(seed instanceof ArrayBuffer) || seed.byteLength !== 64) {
            throw new Error("Seed must be a 64-byte ArrayBuffer");
        }
        const seedView = new Uint8Array(seed);
        let privateKey = BigInt(0);
        for (let i = 0; i < seedView.length; i++) {
            privateKey = (privateKey << BigInt(8)) | BigInt(seedView[i]);
        }
        const mask = (BigInt(1) << BigInt(521)) - BigInt(1);
        privateKey = privateKey & mask;
        privateKey = (privateKey % (P521.N - BigInt(1))) + BigInt(1);
        const publicKey = scalarMul(privateKey, {
            x: P521.GX,
            y: P521.GY
        });
        if (!isOnCurve(publicKey)) {
            throw new Error("Generated public key is not on curve");
        }
        return {
            privateKey,
            publicKey
        };
    }
    this.convertKeys = convertKeys;
    function convertKeys(privateKey, publicKey, cb) {
        function calculateLength(length) {
            if (length < 128) {
                return new Uint8Array([length]);
            } else if (length < 256) {
                return new Uint8Array([0x81, length]);
            }
            return new Uint8Array([0x82, (length >> 8) & 0xFF, length & 0xFF]);
        }
        function convertToPKCS8(privateKey, inner_cb) {
            const isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
            console.log("Browser detected:", isSafari ? "Safari" : "Other browser");
            if (isSafari) {
                console.log("Using Safari-specific deterministic implementation");
                convertSafariPKCS8Deterministic(privateKey, inner_cb);
            } else {
                console.log("Using standard implementation for non-Safari browsers");
                convertStandardPKCS8(privateKey, inner_cb);
            }
            function convertStandardPKCS8(privateKey, inner_cb) {
                function calculateLength(length) {
                    if (length < 128) {
                        return new Uint8Array([length]);
                    } else if (length < 256) {
                        return new Uint8Array([0x81, length]);
                    }
                    return new Uint8Array([0x82, (length >> 8) & 0xFF, length & 0xFF]);
                }
                const privateKeyBytes = new Uint8Array(66);
                let temp = privateKey;
                for (let i = privateKeyBytes.length - 1; i >= 0; i--) {
                    privateKeyBytes[i] = Number(temp & BigInt(0xFF));
                    temp = temp >> BigInt(8);
                }
                const curveOid = new Uint8Array([0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23]);
                const ecPublicKeyOid = new Uint8Array([0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01]);
                const version = new Uint8Array([0x02, 0x01, 0x00]);
                const algorithmSequenceContent = new Uint8Array([...ecPublicKeyOid, ...curveOid]);
                const algoIdLength = calculateLength(algorithmSequenceContent.length);
                const algorithmIdentifier = new Uint8Array([0x30, ...algoIdLength, ...algorithmSequenceContent]);
                const privateKeyOctet = new Uint8Array([0x04, 0x42, ...privateKeyBytes]);
                const parameters = new Uint8Array([0xA0, 0x07, ...curveOid]);
                const ecKeySequenceContent = new Uint8Array([0x02, 0x01, 0x01, ...privateKeyOctet, ...parameters]);
                const ecKeyLength = calculateLength(ecKeySequenceContent.length);
                const ecPrivateKey = new Uint8Array([0x30, ...ecKeyLength, ...ecKeySequenceContent]);
                const ecKeyWrapperLength = calculateLength(ecPrivateKey.length);
                const wrappedEcKey = new Uint8Array([0x04, ...ecKeyWrapperLength, ...ecPrivateKey]);
                const pkcs8Content = new Uint8Array([...version, ...algorithmIdentifier, ...wrappedEcKey]);
                const pkcs8Length = calculateLength(pkcs8Content.length);
                const pkcs8Key = new Uint8Array([0x30, ...pkcs8Length, ...pkcs8Content]);
                try {
                    crypto.subtle.importKey("pkcs8", pkcs8Key.buffer, {
                        name: "ECDH",
                        namedCurve: "P-521"
                    }, true, ["deriveKey", "deriveBits"]).then(function(key) {
                        inner_cb({
                            success: true,
                            key,
                            pkcs8Buffer: pkcs8Key.buffer
                        });
                    }).catch(function(error) {
                        console.error("Standard implementation failed:", error);
                        inner_cb({
                            success: false,
                            error: error.message
                        });
                    });
                } catch (error) {
                    console.error("Exception in standard implementation:", error);
                    inner_cb({
                        success: false,
                        error: error.message
                    });
                }
            }
            function convertSafariPKCS8Deterministic(privateKey, inner_cb) {
                try {
                    console.log("Generating a template key pair using WebCrypto...");
                    crypto.subtle.generateKey({
                        name: "ECDH",
                        namedCurve: "P-521"
                    }, true, ["deriveKey", "deriveBits"]).then(function(keyPair) {
                        console.log("Template key pair generated successfully");
                        crypto.subtle.exportKey("pkcs8", keyPair.privateKey).then(function(exportedKey) {
                            console.log("Template key exported successfully");
                            const pkcs8Template = new Uint8Array(exportedKey);
                            console.log("Template PKCS#8 structure length:", pkcs8Template.length);
                            const privateKeyBytes = new Uint8Array(66);
                            let temp = privateKey;
                            for (let i = privateKeyBytes.length - 1; i >= 0; i--) {
                                privateKeyBytes[i] = Number(temp & BigInt(0xFF));
                                temp = temp >> BigInt(8);
                            }
                            const publicKey = scalarMul(privateKey, {
                                x: P521.GX,
                                y: P521.GY
                            });
                            const xBytes = new Uint8Array(66);
                            let tempX = publicKey.x;
                            for (let i = xBytes.length - 1; i >= 0; i--) {
                                xBytes[i] = Number(tempX & BigInt(0xFF));
                                tempX = tempX >> BigInt(8);
                            }
                            const yBytes = new Uint8Array(66);
                            let tempY = publicKey.y;
                            for (let i = yBytes.length - 1; i >= 0; i--) {
                                yBytes[i] = Number(tempY & BigInt(0xFF));
                                tempY = tempY >> BigInt(8);
                            }
                            const publicKeyBytes = new Uint8Array(133);
                            publicKeyBytes[0] = 0x04;
                            publicKeyBytes.set(xBytes, 1);
                            publicKeyBytes.set(yBytes, 67);
                            const modifiedTemplate = new Uint8Array(pkcs8Template);
                            findAndReplaceKey(modifiedTemplate, privateKeyBytes);
                            findAndReplacePublicKey(modifiedTemplate, publicKeyBytes);
                            crypto.subtle.importKey("pkcs8", modifiedTemplate.buffer, {
                                name: "ECDH",
                                namedCurve: "P-521"
                            }, true, ["deriveKey", "deriveBits"]).then(function(key) {
                                console.log("Deterministic key imported successfully");
                                inner_cb({
                                    success: true,
                                    key,
                                    pkcs8Buffer: modifiedTemplate.buffer
                                });
                            }).catch(function(error) {
                                console.error("Error importing deterministic key:", error);
                                console.log("Fallback: Using template key");
                                crypto.subtle.importKey("pkcs8", pkcs8Template.buffer, {
                                    name: "ECDH",
                                    namedCurve: "P-521"
                                }, true, ["deriveKey", "deriveBits"]).then(function(key) {
                                    console.log("Template key imported as fallback");
                                    inner_cb({
                                        success: true,
                                        key,
                                        pkcs8Buffer: pkcs8Template.buffer,
                                        warning: "Using template key (non-deterministic)"
                                    });
                                }).catch(function(fallbackError) {
                                    console.error("Even fallback failed:", fallbackError);
                                    inner_cb({
                                        success: false,
                                        error: error.message + "/" + fallbackError.message
                                    });
                                });
                            });
                        }).catch(function(error) {
                            console.error("Error exporting template key:", error);
                            inner_cb({
                                success: false,
                                error: error.message
                            });
                        });
                    }).catch(function(error) {
                        console.error("Error generating template key:", error);
                        inner_cb({
                            success: false,
                            error: error.message
                        });
                    });
                } catch (error) {
                    console.error("Exception in Safari implementation:", error);
                    inner_cb({
                        success: false,
                        error: error.message
                    });
                }
            }
            function findAndReplaceKey(template, newKey) {
                for (let i = 0; i < template.length - 68; i++) {
                    if (template[i] === 0x04 && template[i + 1] === 0x42) {
                        console.log("Potential private key location found at index:", i);
                        for (let j = 0; j < 66; j++) {
                            template[i + 2 + j] = newKey[j];
                        }
                        console.log("Private key replaced");
                        return true;
                    }
                }
                console.log("Warning: Private key location not found in template");
                return false;
            }
            function findAndReplacePublicKey(template, newKey) {
                for (let i = 0; i < template.length - 3; i++) {
                    if (template[i] === 0xA1) {
                        let j = i + 1;
                        while (j < template.length && template[j] !== 0x03)
                            j++;
                        if (j < template.length) {
                            j++;
                            while (j < template.length && (template[j] & 0x80))
                                j++;
                            j++;
                            if (j < template.length && template[j] === 0x00) {
                                j++;
                                if (j < template.length && template[j] === 0x04) {
                                    console.log("Public key location found at index:", j);
                                    for (let k = 0; k < newKey.length; k++) {
                                        if (j + k < template.length) {
                                            template[j + k] = newKey[k];
                                        }
                                    }
                                    console.log("Public key replaced");
                                    return true;
                                }
                            }
                        }
                    }
                }
                console.log("Warning: Public key location not found in template");
                return false;
            }
        }
        function convertPublicKeyToRaw(publicKey, inner_cb) {
            const xBytes = new Uint8Array(66);
            let tempX = publicKey.x;
            for (let i = xBytes.length - 1; i >= 0; i--) {
                xBytes[i] = Number(tempX & BigInt(0xFF));
                tempX = tempX >> BigInt(8);
            }
            const yBytes = new Uint8Array(66);
            let tempY = publicKey.y;
            for (let i = yBytes.length - 1; i >= 0; i--) {
                yBytes[i] = Number(tempY & BigInt(0xFF));
                tempY = tempY >> BigInt(8);
            }
            const rawPublicKey = new Uint8Array(133);
            rawPublicKey[0] = 0x04;
            rawPublicKey.set(xBytes, 1);
            rawPublicKey.set(yBytes, 67);
            try {
                crypto.subtle.importKey("raw", rawPublicKey.buffer, {
                    name: "ECDH",
                    namedCurve: "P-521"
                }, true, []).then(function(key) {
                    inner_cb({
                        success: true,
                        key,
                        rawBuffer: rawPublicKey.buffer
                    });
                });
            } catch (error) {
                console.log("Public key import failed with length:", rawPublicKey.length);
                console.log("Full bytes:", Array.from(rawPublicKey).map(b => b.toString(16).padStart(2, '0')).join(' '));
                inner_cb({
                    success: false,
                    error: error.message
                });
            }
        }
        (function init() {
            convertToPKCS8(privateKey, function(privateResult) {
                convertPublicKeyToRaw(publicKey, function(publicResult) {
                    cb({
                        privateKey: privateResult,
                        publicKey: publicResult
                    });
                });
            });
        }
        )();
    }
}
