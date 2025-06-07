# hash-auth

A privacy-focused authentication system that stores only hashed versions of user emails and passwords, designed to minimize the risk of sensitive data exposure in the event of a database leak.

Read more about this project on my blog: [https://pujan.pm/writing/hash-auth](https://pujan.pm/writing/hash-auth)

Live demo: [https://hash-auth.pujan.pm](https://hash-auth.pujan.pm)

## Overview

This project demonstrates a secure approach to user authentication by never storing plaintext emails or passwords. Instead, it uses deterministic hashing for emails and strong, salted password hashing for credentials. The system is inspired by recent data breaches and aims to provide a safer alternative for platforms where user privacy is paramount.

## Technologies Used

- **Bun**: JavaScript runtime for server and cryptography ([bun.sh](https://bun.sh))
- **TypeScript**: Type-safe development
- **SQLite**: Lightweight, file-based relational database
- **bun:sqlite**: Bun's SQLite bindings
- **SHA-256**: Deterministic cryptographic hash for emails
- **Argon2id**: Modern, secure password hashing algorithm

## Hashing Methods

### Email Hashing

- **Algorithm**: SHA-256
- **Salt**: Deterministic, secret salt (set via environment variable `EMAIL_SALT`)
- **Normalization**: Emails are lowercased and trimmed before hashing
- **Purpose**: Prevents duplicate accounts and ensures that the same email always produces the same hash, enabling reliable uniqueness checks without storing the actual email address.

### Password Hashing

- **Algorithm**: Argon2id (via `Bun.password.hash`)
- **Salt**: Random, unique salt generated for each password
- **Purpose**: Ensures that even identical passwords have different hashes, providing strong protection against brute-force and rainbow table attacks.

## Database Structure

- **Engine**: SQLite
- **Table**: `users`
  - `id`: Auto-incrementing primary key
  - `email_hash`: Unique, deterministic hash of the user's email
  - `password_hash`: Argon2id hash of the user's password
  - `created_at`: Timestamp of account creation

No plaintext emails or passwords are ever stored.

## Session Management

- **Type**: In-memory bearer token sessions
- **Authentication**: All protected endpoints require a valid session token in the `Authorization` header

## API Endpoints

- `POST /register`: Register a new user (requires `email` and `password`)
- `POST /login`: Authenticate a user (requires `email` and `password`)
- `GET /users`: Retrieve all user records (requires authentication)
- `POST /reset-password`: Change password (requires authentication, `email`, `currentPassword`, and `newPassword`)
- `POST /logout`: End the current session
- `POST /debug/test-hash`: Test deterministic email hashing (development only)
- `GET /`: API documentation

## Security Considerations

- **No Plaintext Storage**: Neither emails nor passwords are stored in plaintext.
- **Deterministic Email Hashing**: Prevents duplicate accounts and enables user lookup without revealing the original email.
- **Strong Password Hashing**: Argon2id with random salt ensures password hashes are unique and secure.
- **Minimal Data Exposure**: In the event of a database leak, attackers cannot recover user emails or passwords.

## Setup & Usage

### Install dependencies

```bash
bun install
```

### Run the server

```bash
bun run index.ts
```

### Environment Variables

Set a strong, secret salt for email hashing in your environment:

```env
EMAIL_SALT="your-very-long-random-secret"
```

## Example

Register a user:

```bash
curl -X POST http://localhost:5000/register \
  -H "Content-Type: application/json" \
  -d '{"email":"user@example.com","password":"yourpassword"}'
```

## License

[MIT](https://github.com/pujan-modha/hash-auth/blob/main/LICENSE)
