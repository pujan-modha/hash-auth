import { Database } from "bun:sqlite";

export class UserDatabase {
  private db: Database;

  constructor() {
    this.db = new Database("users.db");
    this.init();
  }

  private init() {
    this.db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email_hash TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);
  }

  addUser(emailHash: string, passwordHash: string) {
    const stmt = this.db.prepare(
      "INSERT INTO users (email_hash, password_hash) VALUES (?, ?)"
    );
    return stmt.run(emailHash, passwordHash);
  }

  getUserByEmailHash(emailHash: string) {
    const stmt = this.db.prepare("SELECT * FROM users WHERE email_hash = ?");
    return stmt.get(emailHash);
  }

  getAllUsers() {
    const stmt = this.db.prepare(
      "SELECT id, email_hash, password_hash, created_at FROM users"
    );
    return stmt.all();
  }

  updatePassword(emailHash: string, newPasswordHash: string) {
    const stmt = this.db.prepare(
      "UPDATE users SET password_hash = ? WHERE email_hash = ?"
    );
    return stmt.run(newPasswordHash, emailHash);
  }
}
