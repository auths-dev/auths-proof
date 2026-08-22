declare module "node:fs/promises" {
  interface BigIntStats {
    readonly dev: bigint;
    readonly ino: bigint;
    readonly mode: bigint;
    readonly nlink: bigint;
    readonly size: bigint;
    readonly mtimeNs: bigint;
    readonly ctimeNs: bigint;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  }
  interface Stats {
    readonly mode: number;
    readonly uid: number;
    readonly gid: number;
    isDirectory(): boolean;
    isSocket(): boolean;
    isSymbolicLink(): boolean;
  }
  interface FileHandle {
    writeFile(value: string | Uint8Array): Promise<void>;
    sync(): Promise<void>;
    close(): Promise<void>;
    read(buffer: Uint8Array, offset?: number, length?: number, position?: number): Promise<{ bytesRead: number }>;
    stat(options: { bigint: true }): Promise<BigIntStats>;
  }
  export function mkdir(path: string, options: { recursive: boolean }): Promise<void>;
  export function link(existingPath: string, newPath: string): Promise<void>;
  export function open(path: string, flags: string | number, mode?: number): Promise<FileHandle>;
  export function readFile(path: string): Promise<Uint8Array>;
  export function readFile(path: string, encoding: "utf8"): Promise<string>;
  export function rename(from: string, to: string): Promise<void>;
  export function unlink(path: string): Promise<void>;
  export function lstat(path: string): Promise<Stats>;
  export function lstat(path: string, options: { bigint: true }): Promise<BigIntStats>;
}

declare module "node:fs" {
  export const constants: {
    readonly O_RDONLY: number;
    readonly O_NOFOLLOW?: number;
    readonly O_NONBLOCK?: number;
  };
}

declare module "node:net" {
  interface Socket {
    write(value: Uint8Array): boolean;
    end(callback?: () => void): void;
    destroy(error?: Error): void;
    once(event: "connect" | "end" | "close", listener: () => void): this;
    once(event: "error", listener: (error: Error) => void): this;
    on(event: "data", listener: (chunk: Uint8Array) => void): this;
  }
  export function createConnection(options: { path: string }): Socket;
}

declare module "node:path" {
  export function dirname(path: string): string;
  export function join(...parts: string[]): string;
  export function resolve(path: string): string;
}

declare module "node:os" {
  export function platform(): string;
}
