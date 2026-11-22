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
