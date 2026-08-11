declare module "node:http" {
  const value: any;
  export default value;
}
declare module "node:crypto" {
  export const createHash: any;
  export const createPrivateKey: any;
  export const createPublicKey: any;
  export const generateKeyPairSync: any;
  export const randomBytes: any;
  export const sign: any;
  export const verify: any;
}
declare module "node:fs" {
  export const existsSync: any;
  export const mkdirSync: any;
  export const readFileSync: any;
  export const writeFileSync: any;
}
declare module "node:path" { export const dirname: any; }
declare const process: any;
declare const Buffer: any;
