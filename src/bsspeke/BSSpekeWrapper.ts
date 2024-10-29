
// @ts-ignore
import Module from "./EmccBsspeke.js";

declare global {
  function Module(): any;
}

interface PhfParams {
  name: string;
  blocks: number;
  iterations: number;
}

// Class to wrap the bsspeke client and interact with emscripten compiled code
export class Client {
  private ctx: any;
  private useModule: any; // Module object from emscripten compiled bsspeke code that provides access to the compiled functions
  private moduleInitialized: Promise<void>; // Promise that resolves when the emscripten module is initialized (added for module support of emscripten compiled Bsspeke code)

  public constructor(userId: string, serverId: string, password: string) {
    this.moduleInitialized = new Promise((resolve) => {
      Module().then((Module: any) => {
        this.useModule = Module;

        const uidUtf8 = encodeUTF8(userId);
        // console.log("decoded uid_utf8: ", uidUtf8, "uid_utf8.length: ", uidUtf8.length);
        const sidUtf8 = encodeUTF8(serverId);
        // console.log("sid_utf8: ", sidUtf8, "sid_utf8.length: ", sidUtf8.length);
        const pwdUtf8 = encodeUTF8(password);
        // console.log("pwd_utf8: ", pwdUtf8, "pwd_utf8.length: ", pwdUtf8.length);

        // Calling emscriten compiled bsspeke code to generate client
        this.ctx = this.useModule.ccall("generate_client", "number", [], []);
        // console.log("ctx: ", this.ctx);
        const success = this.useModule.ccall("bsspeke_client_init", "number", ["number", "string", "number", "string", "number", "string", "number"], [this.ctx, uidUtf8, uidUtf8.length, sidUtf8, sidUtf8.length, pwdUtf8, pwdUtf8.length]);
        console.log("Client init success: ", success);
        resolve();
      });
    });
  }

  // Generates a blind for the client
  public async generateBlind(): Promise<Uint8Array> {
    await this.moduleInitialized;

    const blindPointer = this.useModule.ccall("bsspeke_client_generate_blind", "number", ["array", "number"], [new Uint8Array(32), this.ctx]);
    const blind = new Uint8Array(this.useModule.HEAPU8.buffer, blindPointer, 32);
    return blind;
  }

  // Generates P and V hashes for the client
  public generatePAndV(blindSalt: Uint8Array, phfParams: PhfParams): { PArray: Uint8Array; VArray: Uint8Array } {
    const P = this.useModule._malloc(32);
    const V = this.useModule._malloc(32);
    const blocks = phfParams.blocks;
    const iterations = phfParams.iterations;

    this.useModule.ccall("bsspeke_client_generate_P_and_V", "number", ["number", "number", "array", "number", "number", "number"], [P, V, blindSalt, blocks, iterations, this.ctx]);

    const PArray = new Uint8Array(this.useModule.HEAPU8.buffer, P, 32);
    const VArray = new Uint8Array(this.useModule.HEAPU8.buffer, V, 32);

    return { PArray, VArray };
  }

  public generateA(blindSalt: Uint8Array, phfParams: PhfParams): Uint8Array {
    this.useModule.ccall("bsspeke_client_generate_A", "number", ["array", "number", "number", "number"], [blindSalt, phfParams.blocks, phfParams.iterations, this.ctx]);

    // different offset from header file?
    // const AOffset = 256 + 8 + 256 + 8 + 32 + 256 + 8 + 32 + 32 + 32; // 920
    const AOffset = 939;

    const AArray = new Uint8Array(this.useModule.HEAPU8.buffer, this.ctx + AOffset - 31, 32);
    // console.log("Heap buffer: ", this.useModule.HEAPU8.buffer);

    return AArray;
  }

  public deriveSharedKey(b: Uint8Array): void {
    this.useModule.ccall("bsspeke_client_derive_shared_key", null, ["array", "number"], [b, this.ctx]);
  }

  public generateHashedKey(k: Uint8Array, msg: Uint8Array, msgLen: number): Uint8Array {
    const kPointer = this.useModule.ccall("bsspeke_client_generate_hashed_key", "number", ["array", "array", "number", "number"], [k, msg, msgLen, this.ctx]);
    const kArray = new Uint8Array(this.useModule.HEAPU8.buffer, kPointer, 32);

    return kArray;
  }

  public generateVerifier(): Uint8Array {
    const clientVerifier = this.useModule._malloc(32);

    this.useModule.ccall("bsspeke_client_generate_verifier", "number", ["number", "number"], [clientVerifier, this.ctx]);

    const clientVerifierArray = new Uint8Array(this.useModule.HEAPU8.buffer, clientVerifier, 32);

    return clientVerifierArray;
  }
}

function encodeUTF8(str: string): string {

  // Encode the string from UTF-16 to UTF-8
  const encoder = new TextEncoder();
  const utf8Array = encoder.encode(str);

  // Convert the UTF-8 array to a string representation
  const utf8EncodedString = String.fromCharCode(...utf8Array);
  return utf8EncodedString;

}

// Decode a UTF-8 byte array to a stirng
export function decodeUTF8(bytes: Uint8Array): string {
  const utf8Decoder = new TextDecoder("utf-8");
  return utf8Decoder.decode(bytes);
}

export default Client;
