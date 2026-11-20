// A valid TypeScript contract client. The Rust scanner must not parse this.
export interface Vault {
  deposit(amount: bigint): Promise<void>;
  withdraw(amount: bigint): Promise<void>;
}

export function describe(vault: Vault): string {
  return `vault:${vault.deposit.length}:${vault.withdraw.length}`;
}
