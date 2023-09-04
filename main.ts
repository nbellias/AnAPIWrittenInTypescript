
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

import express, { Request, Response } from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import helmet from 'helmet';
import multer from 'multer';
import bodyParser from 'body-parser';
import jwt from 'jsonwebtoken';
import http from 'http';
import https from 'https';
import rateLimit from 'express-rate-limit';
import winston from 'winston';
import path from 'path';
import fs from 'fs';
import swaggerJSDoc from 'swagger-jsdoc';
import swaggerUi from 'swagger-ui-express';

const app = express();
const HTTP_PORT = 43000;
const HTTPS_PORT = 43443;
const SECRET_KEY = 'riUd3qNZ9CPB4cR5jm2S1WYoOw78yvJH'; // Replace with your actual secret key

// Sample data for demonstration
let items: any[] = [];
const users = [
    { id: 1, username: 'user1', password: 'password1' },
    { id: 2, username: 'user2', password: 'password2' }
];
const authenticate = (username: string, password: string): boolean => {
    // In a real-world scenario, you'd verify against a database or another authentication system.
    const user = users.find((u) => u.username === username && u.password === password);
    return !!user;
};

app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.json());

// Logger middleware
// This logs all incoming requests
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.json(),
    transports: [
        new winston.transports.File({ filename: 'error.log', level: 'error' }),
        new winston.transports.File({ filename: 'combined.log' }),
    ],
});
// Logging middleware for requests
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`);
    next();
});

// Handle errors with a middleware
app.use((err: any, req: Request, res: Response, next: Function) => {
    logger.error(err.stack);
    res.status(500).send({ message: 'Something went wrong!' });
});

// Rate limiter middleware
// This helps prevent abuse (like brute-force attacks) 
// by limiting the number of requests a user/IP can make 
// in a given timeframe.
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100  // limit each IP to 100 requests per windowMs
});

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
const storage = multer.memoryStorage(); // Store files in memory for progress tracking
const upload = multer({
    // dest: 'uploads/', // Directory to store uploaded files
    storage,
    limits: { fileSize: 1024 * 1024 * 5 }, // Limit file size to 5 MB
    fileFilter: (req, file, cb) => {
        const allowedTypes = ['.doc', '.docx', '.xls', '.xlsx'];
        const fileExt = path.extname(file.originalname).toLowerCase();
        if (allowedTypes.includes(fileExt)) {
            cb(null, true);
        } else {
            cb(new Error('Invalid file type'));
        }
    },
});

app.use(cors());
app.use(helmet());
app.set('trust proxy', 1);  // Trust the first proxy

// Swagger configuration options
const swaggerOptions: swaggerJSDoc.Options = {
    swaggerDefinition: {
        openapi: '3.0.0',
        info: {
            title: 'Swagger Items - OpenAPI 3.0',
            version: '1.0.2',
            description: 'API documentation for My API [Download the Swagger JSON](https://localhost:43443/swagger.json).',
            contact: {
                name: 'Example Company',
                url: 'https://example.com',
                email: 'nbellias@example.com',
            },
            license: {
                name: 'MIT',
                url: 'https://opensource.org/licenses/MIT',
            },
            termsOfService: 'https://example.com/terms-of-service',
        },
        servers: [
            {
                url: 'http://localhost:43000',
                description: 'Development server',
            },
            {
                url: 'https://localhost:43443',
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
        tags: [
            {
                name: 'Authentication',
                description: 'Endpoints for user authentication',
            },
            {
                name: 'Items',
                description: 'Endpoints for managing items',
            },
            {
                name: 'Upload',
                description: 'Endpoints for uploading files',
            },
        ],
    },
    apis: ['./main.ts'], // Point to your app file
};

const swaggerSpec = swaggerJSDoc(swaggerOptions);

// Serve swagger.json
app.get('/swagger.json', (req: Request, res: Response) => {
    res.setHeader('Content-Type', 'application/json');
    res.send(swaggerSpec);
});

// Serve Swagger UI at /api-docs
app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
    explorer: true, // Show the explorer at the top right
    //customCss: '.swagger-ui .topbar { display: none }', // Hide top bar
    //swaggerUrl: '/swagger.json', // Provide the link to your swagger.json
}));

// Endpoints are defined here

/**
 * @swagger
 * /login:
 *   post:
 *     tags:
 *       - Authentication
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
 *               username: user1
 *               password: password1
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
app.post('/login', (req: Request, res: Response) => {
    const { username, password } = req.body;
    const protocol = req.protocol;

    if (authenticate(username, password)) {
        const userInfo = {
            username,
            // Include other user information as needed.
        };

        // Set the cookie with user information
        res.cookie('userInfo', JSON.stringify(userInfo), {
            httpOnly: true, // Recommended for security.
            secure: (protocol === 'https') ? true : false, // If using HTTPS
            maxAge: 3600000 //1h, Define the cookie expiration time if necessary
        });

        // Generate a JWT token
        const token = jwt.sign({ userId: userInfo.username }, SECRET_KEY, { expiresIn: '1h' });
        res.status(200).json({ token });

        res.status(200).send({ message: 'Login successful' });
    } else {
        res.status(401).send({ message: 'Authentication failed' });
    }

});
// Apply rate limiter middleware to login endpoint
app.use('/login', limiter);

/**
 * @swagger
 * /items:
 *   post:
 *     tags:
 *       - Items
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
 *     tags:
 *       - Items
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
 *     tags:
 *       - Items
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
 *     tags:
 *       - Items
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
 *     tags:
 *       - Upload
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
    async (req, res) => {
        const uploadedFiles = (req.files as Array<Express.Multer.File>).map(async (file: any) => {
            const fileExt = path.extname(file.originalname).toLowerCase();
            const filePath = path.join(__dirname, 'uploads', file.originalname);

            // Write the file from memory to the uploads directory
            await fs.writeFileSync(filePath, file.buffer);

            return {
                originalname: file.originalname,
                size: file.size,
                path: filePath,
            };
        });
        const results = await Promise.all(uploadedFiles);
        res.json({ status: 'success', uploadedFiles: results });
    }
);

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


