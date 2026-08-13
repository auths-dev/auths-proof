declare module "node:fs/promises" {
  interface FileHandle {
    writeFile(value: string | Uint8Array): Promise<void>;
    sync(): Promise<void>;
    close(): Promise<void>;
  }
  export function mkdir(path: string, options: { recursive: boolean }): Promise<void>;
  export function link(existingPath: string, newPath: string): Promise<void>;
  export function open(path: string, flags: string, mode?: number): Promise<FileHandle>;
  export function readFile(path: string): Promise<Uint8Array>;
  export function readFile(path: string, encoding: "utf8"): Promise<string>;
  export function rename(from: string, to: string): Promise<void>;
  export function unlink(path: string): Promise<void>;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
  export function resolve(path: string): string;
}

declare module "node:os" {
  export function platform(): string;
}
