import express from 'express';
import cors from 'cors';
import { MongoClient, ObjectId, ServerApiVersion } from 'mongodb';
import 'dotenv/config';

const app = express();
const PORT = process.env.PORT || 8000;

// CORS configuration
const allowedOrigins = [
  'http://localhost:3000',
  'http://127.0.0.1:3000',
  'http://localhost:3001',
  'http://localhost:5173',
  process.env.CLIENT_URL,
  process.env.CLIENT_URI,
  process.env.FRONTEND_URL,
].filter(Boolean);

app.use(
  cors({
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      const isAllowed =
        allowedOrigins.includes(origin) || origin.endsWith('.vercel.app');
      if (isAllowed) return callback(null, true);
      return callback(new Error(`CORS blocked for origin: ${origin}`));
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  })
);

app.use(express.json());

// Security middleware: verifyToken
export const verifyToken = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).send({ message: 'Unauthorized access: No token provided' });
  }

  const token = authHeader.split(' ')[1];
  if (!token) {
    return res.status(401).send({ message: 'Unauthorized access: Invalid token format' });
  }

  req.token = token;
  next();
};

// Database connection & collections setup
const uri = process.env.MONGODB_URI;
const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

let db;
export let tuitionsCollection;
export let applicationsCollection;
export let usersCollection;
export let destinationCollection;

async function connectDB() {
  try {
    await client.connect();
    db = client.db('mentorlagbe');
    tuitionsCollection = db.collection('tuitions');
    applicationsCollection = db.collection('applications');
    usersCollection = db.collection('user');
    destinationCollection = db.collection('destination');
    console.log('Successfully connected to MongoDB (mentorlagbe)!');
  } catch (err) {
    console.error('MongoDB connection error:', err.message);
  }
}

connectDB();

const getObjectId = (id) => {
  try {
    return new ObjectId(id);
  } catch {
    return null;
  }
};

// ==========================================
// TUITIONS API ROUTES
// ==========================================

// Create a new tuition (Secured)
app.post('/tuitions', verifyToken, async (req, res) => {
  try {
    const data = req.body;
    const doc = {
      ...data,
      monthlyFee: Number(data.monthlyFee) || 0,
      approvalStatus: data.approvalStatus || 'approved',
      isActive: data.isActive !== undefined ? data.isActive : true,
      createdAt: data.createdAt ? new Date(data.createdAt) : new Date(),
    };
    const result = await tuitionsCollection.insertOne(doc);
    res.status(201).send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to create tuition', error: err.message });
  }
});

// Get all tuitions (Public with filters)
app.get('/tuitions', async (req, res) => {
  try {
    const query = {};
    if (req.query.email) {
      query.tutorEmail = req.query.email;
    }
    if (req.query.status) {
      query.approvalStatus = req.query.status;
    }
    if (req.query.subject) {
      query.subject = { $regex: req.query.subject, $options: 'i' };
    }

    let cursor = tuitionsCollection.find(query);

    if (req.query.sort === 'newest' || req.query.sort === '-1') {
      cursor = cursor.sort({ _id: -1 });
    } else if (req.query.sort === 'fee_asc') {
      cursor = cursor.sort({ monthlyFee: 1 });
    } else if (req.query.sort === 'fee_desc') {
      cursor = cursor.sort({ monthlyFee: -1 });
    }

    if (req.query.limit) {
      cursor = cursor.limit(parseInt(req.query.limit, 10));
    }

    const result = await cursor.toArray();
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch tuitions', error: err.message });
  }
});

// Get single tuition by ID (Public)
app.get('/tuitions/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };
    const result = await tuitionsCollection.findOne(query);

    if (!result) {
      return res.status(404).send({ message: 'Tuition not found' });
    }
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to fetch tuition', error: err.message });
  }
});

// Update a tuition (Secured)
app.patch('/tuitions/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const data = { ...req.body };
    delete data._id;

    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };

    const result = await tuitionsCollection.updateOne(query, { $set: data });
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to update tuition', error: err.message });
  }
});

// Delete a tuition (Secured)
app.delete('/tuitions/:id', verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    const objId = getObjectId(id);
    const query = objId ? { $or: [{ _id: objId }, { id: id }] } : { id: id };

    const result = await tuitionsCollection.deleteOne(query);
    res.send(result);
  } catch (err) {
    res.status(500).send({ message: 'Failed to delete tuition', error: err.message });
  }
});

app.get('/', (req, res) => {
  res.send({ status: 'ok', message: 'MentorLagbe server is running fine!' });
});

app.use((err, req, res, next) => {
  if (err instanceof SyntaxError && err.status === 400 && 'body' in err) {
    return res.status(400).json({ message: 'Invalid JSON payload' });
  }
  if (err?.message?.includes('CORS blocked')) {
    return res.status(403).json({ error: err.message });
  }
  console.error(err.stack || err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server is running at http://localhost:${PORT}`);
});

export default app;
