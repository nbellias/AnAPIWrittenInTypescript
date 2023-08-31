"use strict";
/*
Run the following PowerShell command to generate a random secret key:

$secretKey = -join ((65..90) + (97..122) + (48..57) | Get-Random -Count 32 | ForEach-Object { [char]$_ })
$secretKey

After installing openssl from here "https://slproweb.com/products/Win32OpenSSL.html" generate a private key:

openssl genpkey -algorithm RSA -out private-key.pem

Then generate a self-signed certificate:

openssl req -x509 -new -key private-key.pem -out certificate.pem

In Postman first call /login and copy the token
Then call /items with the token in a header with the key Authorization and the value of the token
*/
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const express_1 = __importDefault(require("express"));
const cors_1 = __importDefault(require("cors"));
const body_parser_1 = __importDefault(require("body-parser"));
const jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
const https_1 = __importDefault(require("https"));
const fs_1 = __importDefault(require("fs"));
const swagger_jsdoc_1 = __importDefault(require("swagger-jsdoc"));
const swagger_ui_express_1 = __importDefault(require("swagger-ui-express"));
const app = (0, express_1.default)();
const PORT = process.env.PORT || 3000;
const SECRET_KEY = 'riUd3qNZ9CPB4cR5jm2S1WYoOw78yvJH'; // Replace with your actual secret key
// Sample data for demonstration
let items = [];
const users = [
    { id: 1, username: 'user1', password: 'password1' },
    { id: 2, username: 'user2', password: 'password2' }
];
app.use(body_parser_1.default.json());
// Middleware for JWT token verification
const verifyToken = (req, res, next) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    if (!token) {
        return res.status(403).json({ message: 'Token not provided' });
    }
    jsonwebtoken_1.default.verify(token, SECRET_KEY, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};
// Swagger configuration options
const swaggerOptions = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'My API',
            version: '1.0.0',
            description: 'API documentation for My API',
        },
        components: {
            securitySchemes: {
                bearerAuth: {
                    type: 'http',
                    scheme: 'bearer',
                    bearerFormat: 'JWT',
                },
            },
        },
        security: [
            {
                bearerAuth: [],
            },
        ],
        securityDefinitions: {
            bearerAuth: {
                type: 'apiKey',
                name: 'Authorization',
                in: 'header',
                description: 'Enter your JWT token in the format "Bearer {token}"',
            },
        },
    },
    apis: ['./main.ts'], // Point to your app file
};
const swaggerSpec = (0, swagger_jsdoc_1.default)(swaggerOptions);
// Serve Swagger UI at /api-docs
app.use('/api-docs', swagger_ui_express_1.default.serve, swagger_ui_express_1.default.setup(swaggerSpec));
// Endpoints are defined here
/**
 * @swagger
 * /login:
 *   post:
 *     summary: Login and get a JWT token
 *     requestBody:
 *       description: Provide your username and password for authentication
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               username:
 *                 type: string
 *               password:
 *                 type: string
 *             example:
 *               username: exampleUser
 *               password: yourPassword
 *     responses:
 *       200:
 *         description: Successfully logged in
 *         content:
 *           application/json:
 *             example:
 *               token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
 *       401:
 *         description: Unauthorized - Invalid credentials
 */
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = users.find((u) => u.username === username && u.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid credentials' });
    }
    // Generate a JWT token
    const token = jsonwebtoken_1.default.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ token });
});
/**
 * @swagger
 * /items:
 *   post:
 *     summary: Create a new item
 *     description: Use this endpoint to create a new item by providing item data in the request body.
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *                 description: The name of the item.
 *               description:
 *                 type: string
 *                 description: Description of the item.
 *             example:
 *               name: New Item
 *               description: This is a new item.
 *     responses:
 *       201:
 *         description: Item created successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: Item created successfully.
 *               item:
 *                 id: 123
 *                 name: New Item
 *                 description: This is a new item.
 *       400:
 *         description: Bad request. Invalid input data.
 *       401:
 *         description: Unauthorized. JWT token is missing or invalid.
 *       403:
 *         description: Forbidden. Insufficient permissions.
 */
app.post('/items', verifyToken, (req, res) => {
    const newItem = req.body;
    items.push(newItem);
    res.status(201).json(newItem);
});
/**
 * @swagger
 * /items:
 *   get:
 *     summary: Get a list of items (with optional pagination)
 *     description: Retrieve a list of items. Requires a valid JWT token for authorization.
 *     security:
 *       - bearerAuth: []
 *     parameters:
 *       - in: query
 *         name: page
 *         schema:
 *           type: integer
 *         description: Page index for pagination (optional)
 *     responses:
 *       200:
 *         description: List of items
 *         content:
 *           application/json:
 *             example:
 *               items: [...]
 */
app.get('/items', verifyToken, (req, res) => {
    const page = parseInt(req.query.page) || 1;
    const perPage = 10;
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;
    const paginatedItems = items.slice(startIndex, endIndex);
    res.status(200).json(paginatedItems);
});
app.put('/items/:id', verifyToken, (req, res) => {
    const itemId = parseInt(req.params.id);
    const updatedItem = req.body;
    const index = items.findIndex((item) => item.id === itemId);
    if (index !== -1) {
        items[index] = { ...items[index], ...updatedItem };
        res.status(200).json(items[index]);
    }
    else {
        res.status(404).json({ message: 'Item not found' });
    }
});
app.delete('/items/:id', verifyToken, (req, res) => {
    const itemId = parseInt(req.params.id);
    items = items.filter((item) => item.id !== itemId);
    res.status(204).send();
});
app.use((0, cors_1.default)());
// Create a HTTPS server
const options = {
    key: fs_1.default.readFileSync('./sec/private-key.pem'),
    cert: fs_1.default.readFileSync('./sec/certificate.pem')
};
const server = https_1.default.createServer(options, app);
// Start the server
server.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
