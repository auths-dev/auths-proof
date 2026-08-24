declare module "node:fs/promises" {
  interface Stats {
    readonly size: number;
    isFile(): boolean;
  }

  export function readFile(
    path: URL | string,
  ): Promise<Uint8Array<ArrayBuffer>>;

  export function stat(path: URL | string): Promise<Stats>;
}
