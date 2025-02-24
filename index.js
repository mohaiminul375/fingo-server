const { MongoClient, ServerApiVersion } = require('mongodb');
const express = require('express');
const app = express();
const port = 5000;
const bcrypt = require('bcrypt');
require('dotenv').config();
const cors = require('cors');
// Middleware & Cors
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000'],
    credentials: true
}));
const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.ixszr3u.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

// Create a MongoClient with a MongoClientOptions object to set the Stable API version
const client = new MongoClient(uri, {
    serverApi: {
        version: ServerApiVersion.v1,
        strict: true,
        deprecationErrors: true,
    }
});

async function run() {
    try {
        // DB collection 
        const usersCollections = client.db('fingo-mfs').collection('all-users');



        // Users management and Authentication
        // Create a User
        app.post('/create-user', async (req, res) => {
            try {
                const { name, phone_number, PIN, email, userType, NID } = req.body;
                console.log(req.body)
                // Check for existing user
                const existingUser = await usersCollections.findOne({
                    $or: [
                        { phone_number },
                        { email },
                        { NID }
                    ]
                });

                if (existingUser) {
                    return res.status(400).json({
                        success: false,
                        message: "Phone number, email, or NID already exists."
                    });
                }

                // Hash the PIN (password)
                const hashedPIN = bcrypt.hashSync(PIN, 10);

                // Create user object
                const newUser = {
                    name,
                    phone_number,
                    email,
                    userType,
                    NID,
                    PIN: hashedPIN,
                    createdAt: new Date()
                };

                // Set account status & balance
                if (userType === "Agent") {
                    newUser.account_status = "Pending";
                    newUser.current_balance = 100000;
                } else if (userType === "User") {
                    newUser.account_status = "Active";
                    newUser.current_balance = 40;
                }
                console.log(newUser, 'before insert')
                // Insert new user
                const result = await usersCollections.insertOne(newUser);
                res.status(201).json({
                    success: true,
                    message: "User registered successfully!",
                    userId: result.insertedId
                });

            } catch (error) {
                if (error.code === 11000) {
                    return res.status(400).json({
                        success: false,
                        message: "Duplicate entry: Phone number, email, or NID already exists."
                    });
                }
                console.error("Error registering user:", error);
                res.status(500).json({
                    success: false,
                    message: "Internal server error."
                });
            }
        });
        // TODO: jwt secure
        app.get('/all-users', async (req, res) => {
            try {
                const result = await usersCollections.find().toArray();
                res.status(200).send(result)
            } catch (error) {
                console.error('Error fetching users:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch users list. Please try again later.',
                });
            }

        })

        // Connect the client to the server	(optional starting in v4.7)
        // await client.connect();
        // Send a ping to confirm a successful connection
        await client.db("admin").command({ ping: 1 });
        console.log("Pinged your deployment. You successfully connected to MongoDB!");
    } finally {
        // Ensures that the client will close when you finish/error
        // await client.close();
    }
}
run().catch(console.dir);









// test server
app.get('/', (req, res) => {
    res.send('Hello World!')
});

app.listen(port, () => {
    console.log(`fingo-server app listening on port ${port}`);
});