# ASP.NET Core Authentication and Authorization

This project is a secure and scalable ASP.NET Core application that demonstrates the following features:

- **JWT Authentication**: Secure API endpoints using JSON Web Tokens (JWT).
- **OAuth Integration**: Support for external login providers (e.g., Google, Facebook).
- **Role-Based Authorization**: Manage user roles and permissions.
- **Claims-Based Access Control**: Use claims for fine-grained authorization.
- **User Management**: Register, login, and manage users with ASP.NET Core Identity.

---

## **Features**

- **JWT Authentication**:
  - Secure API endpoints using JWT tokens.
  - Token expiration and validation.

- **OAuth Integration**:
  - Support for external login providers (e.g., Google, Facebook).
  - Store external login tokens securely.

- **Role-Based Authorization**:
  - Assign roles to users (e.g., Admin, User).
  - Restrict access to endpoints based on roles.

- **Claims-Based Access Control**:
  - Add custom claims to users (e.g., `Permission:CanEdit`).
  - Use claims for fine-grained authorization.

- **User Management**:
  - Register new users with email and password.
  - Login with email and password or external providers.
  - Manage user roles and claims.

---

## **Technologies Used**

- **ASP.NET Core**: Backend framework for building RESTful APIs.
- **Entity Framework Core**: ORM for database interactions.
- **JWT**: JSON Web Tokens for authentication.
- **OAuth**: Integration with external login providers.
- **SQL Server**: Database for storing user and role information.

---

## **Getting Started**

### **Prerequisites**

- [.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0)
- [SQL Server](https://www.microsoft.com/en-us/sql-server/sql-server-downloads)
- [Visual Studio 2022](https://visualstudio.microsoft.com/vs/) or [Visual Studio Code](https://code.visualstudio.com/)

### **Setup**

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/sana-ullah305/QuorixJWT.git
   cd QuorixJWT
   ```

2. **Configure the Database**:
   - Update the connection string in `appsettings.json`:
     ```json
     "ConnectionStrings": {
       "DefaultConnection": "Server=(localdb)\\MSSQLLocalDB;Database=QuorixJWT;Trusted_Connection=True;TrustServerCertificate=True;"
     }
     ```
   - Run migrations to create the database:
     ```bash
     dotnet ef database update
     ```

3. **Configure JWT and OAuth**:
   - Update the `Jwt` and `OAuth` settings in `appsettings.json`:
     ```json
     "Jwt": {
       "Issuer": "https://localhost:5001",
       "Audience": "https://localhost:5001",
       "SecretKey": "YOUR_SECRET_KEY",
       "ExpiryInMinutes": 60
     },
     "OAuth": {
       "ClientId": "YOUR_CLIENT_ID",
       "ClientSecret": "YOUR_CLIENT_SECRET",
       "CallbackPath": "/signin-oauth",
       "AuthorizationEndpoint": "https://your-auth-provider.com/authorize",
       "TokenEndpoint": "https://your-auth-provider.com/token"
     }
     ```

4. **Run the Application**:
   ```bash
   dotnet run
   ```

---

## **API Endpoints**

| Method | Endpoint                  | Description                              |
|--------|---------------------------|------------------------------------------|
| POST   | `/api/Account/Register`   | Register a new user.                     |
| POST   | `/api/Account/Login`      | Login and receive a JWT token.           |
| POST   | `/api/Account/Logout`     | Logout the current user.                 |
| GET    | `/api/Account/UserInfo`   | Get information about the current user.  |
| POST   | `/api/Account/AddExternalLogin` | Add an external login provider.     |
| POST   | `/api/Account/RemoveLogin`| Remove an external login provider.       |
| GET    | `/api/Account/ManageInfo` | Get user roles and external login info.  |

---

## **License**

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## **Contributing**

Contributions are welcome! Please follow these steps:

1. Fork the repository.
2. Create a new branch (`git checkout -b feature/YourFeature`).
3. Commit your changes (`git commit -m 'Add some feature'`).
4. Push to the branch (`git push origin feature/YourFeature`).
5. Open a pull request.

---

## **Acknowledgments**

- [ASP.NET Core Documentation](https://learn.microsoft.com/en-us/aspnet/core/)
- [JWT.io](https://jwt.io/)
- [OAuth 2.0](https://oauth.net/2/)
```