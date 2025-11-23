# Auth Service

Microservice for authentication and authorization in the car-sharing platform.

## Features

- User authentication (login/logout)
- JWT token generation and verification
- Refresh token mechanism
- User registration
- Session management with Redis

## Technology Stack

- **Language**: Go 1.21+
- **Framework**: gRPC
- **Database**: PostgreSQL
- **Cache**: Redis
- **Authentication**: JWT with RS256

## API

### gRPC Methods

- `Login` - Authenticate user and return tokens
- `VerifyToken` - Validate JWT token
- `RefreshToken` - Refresh access token using refresh token

### Protobuf

See `car-sharing-protos/proto/auth/auth.proto` for detailed API specification.

## Configuration

### Environment Variables

- `ENV` - Environment (development/production)
- `PORT` - gRPC server port (default: 50051)
- `DATABASE_URL` - PostgreSQL connection string
- `REDIS_URL` - Redis connection string
- `JWT_PRIVATE_KEY_PATH` - Path to RSA private key
- `JWT_PUBLIC_KEY_PATH` - Path to RSA public key
- `JWT_EXPIRATION` - JWT token expiration duration

### Generating JWT Keys

```bash
# Generate private key
openssl genrsa -out private.pem 2048

# Generate public key
openssl rsa -in private.pem -pubout -out public.pem# auth-service
