
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

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import multer from 'multer';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import http from 'http';
import https from 'https';
import fs from 'fs';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';


const app = express();
const HTTP_PORT = 3000;
const HTTPS_PORT = 3443;
const SECRET_KEY = 'riUd3qNZ9CPB4cR5jm2S1WYoOw78yvJH'; // Replace with your actual secret key

// Sample data for demonstration
let items: any[] = [];
const users = [
    { id: 1, username: 'user1', password: 'password1' },
    { id: 2, username: 'user2', password: 'password2' }
];

app.use(bodyParser.json());

// Middleware for JWT token verification
const verifyToken = (req: any, res: any, next: any) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');

    if (!token) {
        return res.status(403).json({ message: 'Token not provided' });
    }

    jwt.verify(token, SECRET_KEY, (err: any, decoded: any) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
};

// Configure multer for file upload
const upload = multer({
    dest: 'uploads/', // Directory to store uploaded files
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.doc', '.docx', '.xls', '.xlsx'];
        const fileExt = file.originalname.split('.').pop();
        if (allowedTypes.includes(`.${fileExt}`)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    },
});

// Swagger configuration options
const swaggerOptions: swaggerJSDoc.Options = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'My Items API',
            version: '1.0.0',
            description: 'API documentation for My API',
            contact: {
                name: 'Example Company',
                url: 'https://example.com',
                email: 'nbellias@exmple.com',
            },
        },
        servers: [
            {
                url: 'http://localhost:3000',
                description: 'Development server',
            },
            {
                url: 'https://localhost:3443',
                description: 'Production server',
            },
        ],
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

const swaggerSpec = swaggerJSDoc(swaggerOptions);

// Serve Swagger UI at /api-docs
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec));

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
    const token = jwt.sign({ userId: user.id }, SECRET_KEY, { expiresIn: '1h' });

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
 *               name: Item 1
 *               description: The item with id=1.
 *     responses:
 *       201:
 *         description: Item created successfully.
 *         content:
 *           application/json:
 *             example:
 *               message: Item created successfully.
 *               item:
 *                 id: 1
 *                 name: Item 1
 *                 description: The item with id=1.
 *       400:
 *         description: Bad request. Invalid input data.
 *       401:
 *         description: Unauthorized. JWT token is missing or invalid.
 *       403:
 *         description: Forbidden. Insufficient permissions.
 */
app.post('/items', verifyToken, (req, res) => {
    const newItem = req.body;
    const id = items.length + 1;
    items.push({ ...{ id: id }, ...newItem });
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
    const page = parseInt(req.query.page as string) || 1;
    const perPage = 10;
    const startIndex = (page - 1) * perPage;
    const endIndex = startIndex + perPage;

    const paginatedItems = items.slice(startIndex, endIndex);
    res.status(200).json(paginatedItems);
});

/**
 * @swagger
 * /items/{id}:
 *   put:
 *     summary: Update an item by ID
 *     parameters:
 *       - name: id
 *         in: path
 *         description: ID of the item to update
 *         required: true
 *         schema:
 *           type: string
 *     requestBody:
 *       description: Updated item information
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             type: object
 *             properties:
 *               name:
 *                 type: string
 *               description:
 *                 type: string
 *     responses:
 *       200:
 *         description: Successfully updated the item
 *       400:
 *         description: Bad request, invalid input data
 *       404:
 *         description: Item not found
 */
app.put('/items/:id', verifyToken, (req, res) => {
    const itemId = parseInt(req.params.id);
    const updatedItem = req.body;

    const index = items.findIndex((item) => item.id === itemId);
    if (index !== -1) {
        items[index] = { ...items[index], ...updatedItem };
        res.status(200).json(items[index]);
    } else {
        res.status(404).json({ message: 'Item not found' });
    }
});

/**
 * @swagger
 * /items/{id}:
 *   delete:
 *     summary: Delete an item by ID
 *     parameters:
 *       - name: id
 *         in: path
 *         description: ID of the item to delete
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       204:
 *         description: Item deleted successfully
 *       404:
 *         description: Item not found
 *       500:
 *         description: Server error
 */
app.delete('/items/:id', verifyToken, (req, res) => {
    const itemId = parseInt(req.params.id);

    items = items.filter((item) => item.id !== itemId);
    res.status(204).send();
});

/**
 * @swagger
 * /upload:
 *   post:
 *     summary: Upload multiple files of specific types
 *     security:
 *       - bearerAuth: []
 *     requestBody:
 *       content:
 *         multipart/form-data:
 *           schema:
 *             type: object
 *             properties:
 *               files:
 *                 type: array
 *                 items:
 *                   type: string
 *                   format: binary
 *     responses:
 *       200:
 *         description: Successfully uploaded files
 *         content:
 *           application/json:
 *             example:
 *               status: success
 *               uploadedFiles: [file1.jpg, file2.pdf]
 *       400:
 *         description: Bad request, invalid input data or file type
 *       403:
 *         description: Forbidden, authentication failed
 */
app.post(
    '/upload',
    verifyToken,
    upload.array('files', 5), // Max 5 files
    (req, res, err) => {
        if (err instanceof multer.MulterError) {
            if (err.code === 'LIMIT_UNEXPECTED_FILE') {
                return res.status(400).json({ error: 'Too many files' });
            }
        } else if (err) {
            return res.status(400).json({ error: err });
        }
        const uploadedFiles = (req.files as Array<Express.Multer.File>).map((file: any) => file.originalname);
        res.json({ status: 'success', uploadedFiles });
    },
);

app.use(cors());
app.use(helmet());

// Create a HTTP server
const http_server = http.createServer(app);

// Create a HTTPS server
const options = {
    key: fs.readFileSync('./sec/private-key.pem'),
    cert: fs.readFileSync('./sec/certificate.pem')
};
const https_server = https.createServer(options, app);

// Start the HTTP server
http_server.listen(HTTP_PORT, () => {
    console.log(`HTTP Server is running on port ${HTTP_PORT}`);
});
// And the HTTPS Server
https_server.listen(HTTPS_PORT, () => {
    console.log(`HTTPS Server is running on port ${HTTPS_PORT}`);
});


