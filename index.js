const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const express = require('express');
const app = express();
const port = 5000;
const bcrypt = require('bcrypt');
require('dotenv').config();
const jwt = require('jsonwebtoken');
const cors = require('cors');
// Middleware & Cors
app.use(express.json());
app.use(cors({
    origin: ['http://localhost:3000', "https://fingo-cash.vercel.app"],
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
// Authentication middleware
const authenticateUser = (req, res, next) => {
    const token = req.headers.authorization?.split(" ")[1]; // Extract token from Authorization header
    console.log(token)
    if (!token) {
        return res.status(401).json({ error: 'Access denied' });
    }

    try {
        // Decode and verify the token
        const verified = jwt.verify(token, process.env.JWT_SECRET);
        req.user = verified;
        console.log(verified)

        next();
    } catch (err) {
        res.status(403).json({ error: 'Unauthorized: Invalid token' });
    }
};
async function run() {
    try {
        // DB collection 
        const usersCollections = client.db('fingo-mfs').collection('all-users');
        const trxCollections = client.db('fingo-mfs').collection('all-transactions')
        const agentMoneyReqCollections = client.db('fingo-mfs').collection('all-agent-money-request')
        const agentWithdrawReqCollections = client.db('fingo-mfs').collection('all-agent-withdraw-request')

        /**** ADMIN DASHBOARD *****/
        // Users management and Authentication
        // Create a User
        app.post('/create-user', async (req, res) => {
            try {
                const { name, phone_number, PIN, email, userType, NID } = req.body;
                // console.log(req.body);

                // Check for existing user
                const existingUser = await usersCollections.findOne({
                    $or: [{ phone_number }, { email }, { NID }]
                });

                if (existingUser) {
                    return res.status(400).json({
                        success: false,
                        message: "Phone number, email, or NID already exists."
                    });
                }

                // Hash the PIN
                const hashedPIN = bcrypt.hashSync(PIN, 10);

                // Create new user object
                const newUser = {
                    name,
                    phone_number,
                    email,
                    userType,
                    NID,
                    PIN: hashedPIN,
                    createdAt: new Date(),
                };

                // Set account status & balance
                let bonusAmount = 0;
                if (userType === "Agent") {
                    newUser.account_status = "Pending";
                    newUser.current_balance = 100000;
                    newUser.total_income = 0;
                    bonusAmount = 100000;
                } else if (userType === "User") {
                    newUser.account_status = "Active";
                    newUser.current_balance = 40;
                    bonusAmount = 40;
                }

                console.log(newUser, 'before insert');

                // Insert new user
                const result = await usersCollections.insertOne(newUser);

                if (result.insertedId) {
                    // Create transaction record for the new user bonus
                    const newTrx = {
                        method: 'New_user_bonus',
                        sender_name: 'Fingo-mfs',
                        sender_phone: 'Fingo-mfs@support',
                        receiver_name: name,
                        receiver_phone: phone_number,
                        amount: bonusAmount,
                        createdAt: new Date()
                    };
                    const trxResult = await trxCollections.insertOne(newTrx);
                    // Throw error if doesn't found insertedId
                    if (!trxResult.insertedId) {
                        return res.status(500).json({
                            success: false,
                            message: "User registered, but transaction could not be recorded."
                        });
                    }
                }
                // Return if success 
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

        // login user
        app.post('/login', async (req, res) => {
            console.log('server hited')
            const { emailOrPhone, PIN } = req.body;
            console.log(req.body)

            // Validate request body
            if (!emailOrPhone || !PIN) {
                return res.status(400).json({ error: 'All fields are required' });
            }

            try {
                // Find user by email or phone_number
                const user = await usersCollections.findOne({
                    $or: [{ email: emailOrPhone }, { phone_number: emailOrPhone }]
                });

                if (!user) {
                    return res.status(400).json({ error: 'User not found' });
                }

                // Check if user is banned
                if (user?.status === 'Blocked') {
                    return res.status(403).json({ error: 'Your account is Blocked. Please contact support.' });
                }

                // Compare password with the stored hash
                const isMatch = await bcrypt.compare(PIN, user.PIN);
                if (!isMatch) {
                    return res.status(400).json({ error: 'Invalid credentials' });
                }

                // Generate JWT token, excluding sensitive fields
                const { PIN: _, ...userInfo } = user;
                const token = jwt.sign(
                    {
                        id: user._id,
                        name: user.name,
                        phone_number: user.phone_number,
                        email: user.email,
                        userType: user.userType,
                        NID: user.NID,
                        account_status: user.account_status,
                        current_balance: user.current_balance,
                    },
                    process.env.JWT_SECRET,
                    { expiresIn: '12h' }
                );

                // Respond with the token and success message
                res.json({ success: true, token, message: 'Login successful' });
            } catch (err) {
                console.error('Error during login:', err);
                res.status(500).json({ error: 'Internal server error' });
            }
        })
        // TODO: jwt secure
        app.get('/all-users-admin', async (req, res) => {
            try {
                const result = await usersCollections
                    .find({}, { projection: { PIN: 0 } }) // Exclude PIN
                    .sort([
                        { userType: -1 }, //  descending order
                        { createdAt: -1 } // descending order
                    ]).toArray();
                res.status(200).send(result);
            } catch (error) {
                console.error('Error fetching users:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch users list. Please try again later.',
                });
            }
        });
        // get user info
        app.get('/user', authenticateUser, async (req, res) => {
            try {
                // Find the user by email (from the decoded JWT)
                const user = await usersCollections.findOne({ email: req.user.email });
                console.log(user);

                if (!user) {
                    return res.status(404).json({ message: "User not found" });
                }
                // Remove password from the user object
                const { PIN, ...userWithoutPin } = user;

                res.status(200).json({ user: userWithoutPin });
            } catch (error) {
                console.error(error);
                res.status(500).json({ message: "Error fetching user data" });
            }
        });
        // get all transaction
        app.get('/all-transactions-admin', async (req, res) => {
            try {
                const result = await trxCollections.find().sort({ createdAt: -1 }).toArray();     // descending order

                res.status(200).send(result);
            } catch (error) {
                console.error('Error fetching transactions data:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch transactions data. Please try again later.',
                });
            }
        })
        app.get('/all-pending-agent-admin', async (req, res) => {
            try {
                const result = await usersCollections.find({ userType: 'Agent', account_status: 'Pending' }).toArray();
                res.status(200).send(result)
            } catch (error) {
                console.error('Error fetching approval agent data:', error);
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch approval agent data. Please try again later.',
                });
            }

        })
        // Approve or verify agent
        app.put('/agent-approval-admin/:id', async (req, res) => {
            try {
                const id = req.params.id;
                const { account_status } = req.body;
                console.log(id, account_status)
                const query = { _id: new ObjectId(id) };
                const option = { upsert: true };
                const updateDoc = {
                    $set: {
                        account_status: account_status,
                        approvedAt: new Date(),
                    }
                };

                const result = await usersCollections.updateOne(query, updateDoc, option,);
                // Send success response
                res.status(200).send(result);
            } catch (error) {
                // Handle errors
                console.error('Error during agent approval:', error);
                res.status(500).send({
                    success: false,
                    message: 'Failed to update agent approval. Please try again later.',
                    error: error.message || 'Unknown error',
                });
            }
        });

        // Agent Cash Requests
        app.get('/all-cashRequest-agent', async (req, res) => {
            try {
                const result = await agentMoneyReqCollections.find({ status: 'pending' }).sort({ createdAt: -1 }).toArray()
                res.status(200).send(result)
            } catch (error) {
                res.status(500).json({
                    success: false,
                    message: 'Failed to fetch Request data. Please try again later.',
                });
            }
        })









        // Method for Agent
        // Verify information during cashIn
        app.post('/verify-cashIn', async (req, res) => {
            const {
                PIN,
                agent_name,
                agent_phone_number,
                cashIn,
                method,
                user_phone_number,
                trx_amount
            } = req.body;
            console.log(req.body)
            // Ensure the method is cashIn
            if (method !== 'cashIn') {
                return res.status(400).json({ error: 'Invalid method' });
            }

            // Verify agent's phone number and PIN
            const verifyAgent = await usersCollections.findOne({ phone_number: agent_phone_number });
            if (!verifyAgent) {
                return res.status(404).json({ error: 'Agent not found' });
            }

            const isMatch = await bcrypt.compare(PIN, verifyAgent.PIN);
            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            // Verify receiver's phone number
            const verifyReceiver = await usersCollections.findOne({ phone_number: user_phone_number });
            if (!verifyReceiver) {
                return res.status(404).json({ error: 'Receiver not found' });
            }
            if (verifyReceiver.userType !== 'User') {
                return res.status(404).json({ error: 'Receiver must a customer' });
            }
            let user_name = verifyReceiver.name
            // Verified info send to front-end
            const verifiedTransaction = {
                method,
                agent_name,
                agent_phone_number,
                cashIn,
                user_name,
                user_phone_number,
                amount: trx_amount
            };

            // Send response with verified transaction details
            return res.status(200).json({ verifiedTransaction });
        });

        // Complete CashIN
        app.post('/complete-cashIn', async (req, res) => {
            const { method, agent_name, agent_phone_number, user_name, user_phone_number, amount } = req.body;

            try {
                // Get Agent
                const verifyAgent = await usersCollections.findOne({ phone_number: agent_phone_number });
                if (!verifyAgent) {
                    return res.status(404).json({ error: 'Agent not found' });
                }

                // Get Receiver
                const verifyReceiver = await usersCollections.findOne({ phone_number: user_phone_number });
                if (!verifyReceiver) {
                    return res.status(404).json({ error: 'Receiver not found' });
                }

                // Calculate Agent Balance and income minus form balance and add to income 1% of trx amount
                const parsedAmount = parseFloat(amount);
                const agentBalanceCalculation = verifyAgent.current_balance - parsedAmount;
                const agentIncomeCalculation = verifyAgent.total_income + parsedAmount * 0.01;

                // Calculate Receiver balance add amount to balance
                const customerBalanceCalculation = verifyReceiver.current_balance + parsedAmount;

                // Log the calculations for debugging
                // console.log(agentBalanceCalculation, agentIncomeCalculation, customerBalanceCalculation);

                // Create transaction object
                const newTrx = { method, agent_name, agent_phone_number, user_name, user_phone_number, amount: parsedAmount, createdAt: new Date() };
                console.log(newTrx);

                // Insert transaction into the collection
                const createTrx = await trxCollections.insertOne(newTrx);
                if (!createTrx.acknowledged) {
                    return res.status(500).json({ error: 'Failed to create transaction' });
                }

                // Update Agent Balance and Income
                const agentAccountUpdate = await usersCollections.updateOne(
                    { phone_number: agent_phone_number },
                    {
                        $set: {
                            current_balance: agentBalanceCalculation,
                            total_income: agentIncomeCalculation,
                        }
                    }
                );
                if (agentAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update agent account' });
                }

                // Update Receiver Balance
                const receiverAccountUpdate = await usersCollections.updateOne(
                    { phone_number: receiver_phone_number },
                    {
                        $set: {
                            current_balance: customerBalanceCalculation,
                        }
                    }
                );
                if (receiverAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update receiver account' });
                }

                // Final success response
                return res.status(200).json({ message: 'Transaction completed successfully' });

            } catch (error) {
                console.error('Error in /complete-cashIn:', error);
                return res.status(500).json({ error: 'An error occurred while processing the transaction' });
            }
        });

        // Money Request
        app.post('/request-money-agent', async (req, res) => {
            try {
                const { agent_name, agent_number } = req.body;
                if (!agent_name || !agent_number) {
                    return res.status(400).json({
                        success: false,
                        message: 'Agent name and phone number are required.'
                    });
                }
                const verifyAgent = await usersCollections.findOne({ phone_number: agent_number })
                if (verifyAgent.userType !== 'Agent') {
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to verify Agent. Please try again.'
                    });
                }
                const newReq = {
                    agent_name,
                    agent_phone_number: agent_number,
                    request_amount: 100000,
                    requestedAt: new Date(),
                    status: "pending"
                };
                const result = await agentMoneyReqCollections.insertOne(newReq);

                if (!result.acknowledged) {
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to create money request. Please try again.'
                    });
                }
                res.status(201).json({
                    success: true,
                    message: 'Money request submitted successfully.',
                    requestId: result.insertedId
                });
            } catch (error) {
                console.error('Error creating money request:', error);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error. Please try again later.'
                });
            }
        });
        // Withdraw Request
        app.post('/request-withdraw-agent', async (req, res) => {
            try {
                const { agent_name, agent_number, withdrawAmount } = req.body;
                if (!agent_name || !agent_number) {
                    return res.status(400).json({
                        success: false,
                        message: 'Agent name and phone number are required.'
                    });
                }
                // Verify Agent
                const verifyAgent = await usersCollections.findOne({ phone_number: agent_number })
                if (verifyAgent.userType !== 'Agent') {
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to verify Agent. Please try again.'
                    });
                }
                const newReq = {
                    agent_name,
                    agent_phone_number: withdrawAmount,
                    request_amount: 100000,
                    requestedAt: new Date(),
                    status: "pending"
                };
                const result = await agentWithdrawReqCollections.insertOne(newReq);

                if (!result.acknowledged) {
                    return res.status(500).json({
                        success: false,
                        message: 'Failed to create Withdraw request. Please try again.'
                    });
                }
                res.status(201).json({
                    success: true,
                    message: 'withdraw request submitted successfully.',
                    requestId: result.insertedId
                });
            } catch (error) {
                console.error('Error creating withdraw request:', error);
                res.status(500).json({
                    success: false,
                    message: 'Internal server error. Please try again later.'
                });
            }
        });


        // Method for user
        // Verify information during sendMoney
        app.post('/verify-sendMoney', async (req, res) => {
            const {
                PIN,
                sender_name,
                sender_phone_number,
                cashIn,
                method,
                receiver_phone_number,
                trx_amount
            } = req.body;
            console.log(req.body)
            // Ensure the method is cashIn
            if (sender_phone_number === receiver_phone_number) {
                return res.status(400).json({ error: 'Invalid method' });
            }
            if (method !== 'sendMoney') {
                return res.status(400).json({ error: 'Invalid method' });
            }

            // Verify Sender's phone number and PIN
            const verifySender = await usersCollections.findOne({ phone_number: sender_phone_number });
            if (!verifySender) {
                return res.status(404).json({ error: 'Sender not found' });
            }

            const isMatch = await bcrypt.compare(PIN, verifySender.PIN);
            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            // Verify receiver's phone number
            const verifyReceiver = await usersCollections.findOne({ phone_number: receiver_phone_number });
            if (!verifyReceiver) {
                return res.status(404).json({ error: 'Receiver not found' });
            }
            if (verifyReceiver.userType !== 'User') {
                return res.status(404).json({ error: 'Receiver is not valid' });
            }
            let receiver_name = verifyReceiver.name;
            // Parse amount
            let trx_charge = 0;
            const parsedAmount = parseFloat(trx_amount);
            if (parsedAmount > 100) {
                trx_charge = 5
            }
            // Verified info send to front-end
            const verifiedTransaction = {
                method,
                sender_name,
                sender_phone_number,
                cashIn,
                receiver_name,
                receiver_phone_number,
                amount: trx_amount,
                trx_charge,
            };

            // Send response with verified transaction details
            return res.status(200).json({ verifiedTransaction });
        });


        app.post('/complete-sendMoney', async (req, res) => {
            const { method, sender_name, sender_phone_number, receiver_name, receiver_phone_number, amount, trx_charge } = req.body;

            try {
                // Get Agent
                const verifySender = await usersCollections.findOne({ phone_number: sender_phone_number });
                if (!verifySender) {
                    return res.status(404).json({ error: 'Sender not found' });
                }

                // Get Receiver
                const verifyReceiver = await usersCollections.findOne({ phone_number: receiver_phone_number });
                if (!verifyReceiver) {
                    return res.status(404).json({ error: 'Receiver not found' });
                }

                // Calculate Agent Balance and income minus form balance and add to income 1% of trx amount
                const parsedAmount = parseFloat(amount);
                const parsedCharge = parseFloat(trx_charge)
                const senderBalanceCalculation = verifySender.current_balance - parsedAmount - parsedCharge;

                // Calculate Receiver balance add amount to balance
                const receiverBalanceCalculation = verifyReceiver.current_balance + parsedAmount;

                // Log the calculations for debugging
                console.log(receiverBalanceCalculation, senderBalanceCalculation);

                // Create transaction object
                const newTrx = { method, sender_name, sender_phone_number, receiver_name, receiver_phone_number, amount: parsedAmount, createdAt: new Date(), trx_charge };
                console.log(newTrx);

                // Insert transaction into the collection
                const createTrx = await trxCollections.insertOne(newTrx);
                if (!createTrx.acknowledged) {
                    return res.status(500).json({ error: 'Failed to create transaction' });
                }

                // Update Sender Balance and Income
                const senderAccountUpdate = await usersCollections.updateOne(
                    { phone_number: sender_phone_number },
                    {
                        $set: {
                            current_balance: senderBalanceCalculation,
                        }
                    }
                );
                if (senderAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update agent account' });
                }

                // Update Receiver Balance
                const receiverAccountUpdate = await usersCollections.updateOne(
                    { phone_number: receiver_phone_number },
                    {
                        $set: {
                            current_balance: receiverBalanceCalculation,
                        }
                    }
                );
                if (receiverAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update receiver account' });
                }
                // updateAdmin account add will trx_charge
                const updateAdminIncome = await usersCollections.updateOne(
                    { userType: 'Admin' },
                    { $inc: { total_income: trx_charge } }
                );
                if (updateAdminIncome.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update admin account' });
                }
                // Final success response
                return res.status(200).json({ success: true, message: 'Transaction completed successfully' });

            } catch (error) {
                console.error('Error in /complete-cashIn:', error);
                return res.status(500).json({ error: 'An error occurred while processing the transaction' });
            }
        });


        // Verify information during cash out
        app.post('/verify-cashOut', async (req, res) => {
            const {
                PIN,
                user_name,
                user_phone_number,
                cashIn,
                method,
                agent_phone_number,
                trx_amount
            } = req.body;
            console.log(req.body)
            // Ensure the method is cashIn
            if (user_phone_number === agent_phone_number) {
                return res.status(400).json({ error: 'Invalid method' });
            }
            if (method !== 'cashOut') {
                return res.status(400).json({ error: 'Invalid method' });
            }

            // Verify Sender's phone number and PIN
            const verifySender = await usersCollections.findOne({ phone_number: user_phone_number });
            if (!verifySender) {
                return res.status(404).json({ error: 'Sender not found' });
            }

            const isMatch = await bcrypt.compare(PIN, verifySender.PIN);
            if (!isMatch) {
                return res.status(400).json({ error: 'Invalid credentials' });
            }

            // Verify receiver agent's phone number
            const verifyAgent = await usersCollections.findOne({ phone_number: agent_phone_number });
            if (!verifyAgent) {
                return res.status(404).json({ error: 'Receiver not found' });
            }
            if (verifyAgent.userType !== 'Agent') {
                return res.status(404).json({ error: 'Receiver is not valid' });
            }
            let agent_name = verifyAgent.name;
            // Parse amount
            const parsedAmount = parseFloat(trx_amount);
            // if (parsedAmount > 100) {
            //     trx_charge = 5
            // }
            const calculateTrxAmount = parsedAmount * 0.015;
            // Verified info send to front-end
            const verifiedTransaction = {
                method,
                user_name,
                user_phone_number,
                cashIn,
                agent_name,
                agent_phone_number,
                amount: trx_amount,
                trx_charge: calculateTrxAmount,
            };

            // Send response with verified transaction details
            return res.status(200).json({ verifiedTransaction });
        });

        //complete cash out
        app.post('/complete-cashOut', async (req, res) => {
            const { method, user_name, user_phone_number, agent_name, agent_phone_number, amount, trx_charge } = req.body;

            try {
                // Get Agent
                const verifyUser = await usersCollections.findOne({ phone_number: user_phone_number });
                if (!verifyUser) {
                    return res.status(404).json({ error: 'Sender not found' });
                }

                // Get Receiver
                const verifyAgent = await usersCollections.findOne({ phone_number: agent_phone_number });
                if (!verifyAgent) {
                    return res.status(404).json({ error: 'Receiver not found' });
                }

                // Calculate Agent Balance and income minus form balance and add to income 1% of trx amount
                const parsedAmount = parseFloat(amount);
                const parsedCharge = parseFloat(trx_charge)
                const senderBalanceCalculation = verifyUser.current_balance - parsedAmount - parsedCharge;

                // Calculate Receiver balance add amount to balance
                const agentBalanceCalculation = verifyAgent.current_balance + parsedAmount;
                const agentIncomeCalculation = verifyAgent.total_income + parsedAmount * 0.01;
                const adminIncomeCalculation = parsedAmount * 0.005;
                // Log the calculations for debugging
                console.log(agentBalanceCalculation, senderBalanceCalculation);

                // Create transaction object
                const newTrx = { method, user_name, user_phone_number, agent_name, agent_phone_number, amount: parsedAmount, createdAt: new Date(), trx_charge };
                console.log(newTrx);

                // Insert transaction into the collection
                const createTrx = await trxCollections.insertOne(newTrx);
                if (!createTrx.acknowledged) {
                    return res.status(500).json({ error: 'Failed to create transaction' });
                }

                // Update Sender Balance and Income
                const senderAccountUpdate = await usersCollections.updateOne(
                    { phone_number: user_phone_number },
                    {
                        $set: {
                            current_balance: senderBalanceCalculation,
                        }
                    }
                );
                if (senderAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update agent account' });
                }

                // Update Receiver Balance
                const receiverAccountUpdate = await usersCollections.updateOne(
                    { phone_number: agent_phone_number },
                    {
                        $set: {
                            current_balance: agentBalanceCalculation,
                            total_income: agentIncomeCalculation,
                        }
                    }
                );
                if (receiverAccountUpdate.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update receiver account' });
                }
                // updateAdmin account add will trx_charge
                const updateAdminIncome = await usersCollections.updateOne(
                    { userType: 'Admin' },
                    { $inc: { total_income: adminIncomeCalculation } }
                );
                if (updateAdminIncome.modifiedCount === 0) {
                    return res.status(500).json({ error: 'Failed to update admin account' });
                }
                // Final success response
                return res.status(200).json({ success: true, message: 'Transaction completed successfully' });

            } catch (error) {
                console.error('Error in /complete-cashIn:', error);
                return res.status(500).json({ error: 'An error occurred while processing the transaction' });
            }
        });

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